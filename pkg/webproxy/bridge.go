package webproxy

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// PermissionsPolicy disables browser features that the HTTPS bridge does not
// use. It is intentionally exported so an integrating TLS terminator can test
// that it preserves the header unchanged.
const PermissionsPolicy = "accelerometer=(), autoplay=(), camera=(), clipboard-read=(), clipboard-write=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-create=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=(), web-share=(), xr-spatial-tracking=()"

// BridgePage is one self-contained, per-request HTTPS carrier document.
type BridgePage struct {
	Body  []byte
	Nonce string
	CSP   string
}

// RenderBridge constructs the backward-compatible serialized HTTPS bridge.
func RenderBridge(hostname, bootstrapToken string, batchBytes int) (BridgePage, error) {
	return RenderBridgeForCarrier(hostname, bootstrapToken, batchBytes, CarrierHTTPS)
}

// RenderBridgeForCarrier constructs one WEB bridge for the selected carrier.
// The bootstrap token exists only in this no-store response, never in a URL.
func RenderBridgeForCarrier(
	hostname string,
	bootstrapToken string,
	batchBytes int,
	carrier CarrierMode,
) (BridgePage, error) {
	if err := ValidateHostname(hostname); err != nil {
		return BridgePage{}, err
	}
	if _, err := parseTokenHash(bootstrapToken); err != nil {
		return BridgePage{}, ErrAuthentication
	}
	if batchBytes <= 0 || batchBytes > maxCarrierBatchBytes {
		return BridgePage{}, errors.New("WEB bridge batch size is out of range")
	}
	if !carrier.valid() {
		return BridgePage{}, errors.New("WEB bridge carrier mode is unsupported")
	}

	var rawNonce [18]byte
	if _, err := rand.Read(rawNonce[:]); err != nil {
		return BridgePage{}, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(rawNonce[:])
	originJSON, _ := json.Marshal("https://" + hostname)
	tokenJSON, _ := json.Marshal(bootstrapToken)
	carrierJSON, _ := json.Marshal(carrier)
	body := strings.NewReplacer(
		"__NONCE__", nonce,
		"__ORIGIN__", string(originJSON),
		"__BOOTSTRAP__", string(tokenJSON),
		"__CARRIER__", string(carrierJSON),
		"__BATCH_LIMIT__", strconv.Itoa(batchBytes),
	).Replace(bridgeDocument)
	if strings.Contains(body, "__NONCE__") || strings.Contains(body, "__ORIGIN__") ||
		strings.Contains(body, "__BOOTSTRAP__") || strings.Contains(body, "__CARRIER__") ||
		strings.Contains(body, "__BATCH_LIMIT__") {
		return BridgePage{}, errors.New("WEB bridge template replacement failed")
	}

	return BridgePage{
		Body:  []byte(body),
		Nonce: nonce,
		CSP: strings.Join([]string{
			"default-src 'none'",
			"base-uri 'none'",
			"child-src 'none'",
			"connect-src 'self'",
			"font-src 'none'",
			"form-action 'none'",
			"frame-ancestors http://127.0.0.1:*",
			"frame-src 'none'",
			"img-src 'none'",
			"manifest-src 'none'",
			"media-src 'none'",
			"object-src 'none'",
			"script-src 'nonce-" + nonce + "'",
			"style-src 'none'",
			"worker-src 'none'",
			"sandbox allow-same-origin allow-scripts",
		}, "; "),
	}, nil
}

// The bridge is self-contained and has no external resources.
const bridgeDocument = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connection</title>
</head>
<body>
<script nonce="__NONCE__">
(()=>{
'use strict';
const relayOrigin=__ORIGIN__,bootstrap=__BOOTSTRAP__,carrier=__CARRIER__,batchLimit=__BATCH_LIMIT__;
const match=/^#android=([A-Za-z0-9_-]{43})$/.exec(location.hash),androidNonce=match?match[1]:'';
history.replaceState(null,'',location.pathname);
const queueByteLimit=33554432,queueItemLimit=16384,maxFrames=4096,maxPayload=1048576,closedLaneLimit=4096;
let initialized=false,closed=false,port=null,sessionToken='',createStarted=false;
let queuedBytes=0,queuedItems=0,upSequence=1,downCursor='0',upRunning=false,pollController=null;
const lifecycleController=new AbortController();
const beforeSession=[],upPending=[];
const lanes=new Map(),closedLanes=new Set(),closedLaneOrder=[];
const status=state=>{if(port&&!closed)port.postMessage({t:'status',state})};
function ensureOpen(external){if(closed||lifecycleController.signal.aborted||(external&&external.aborted))throw new DOMException('carrier closed','AbortError')}
function pause(milliseconds,external){
 ensureOpen(external);return new Promise((resolve,reject)=>{
  let timer;const abort=()=>{clearTimeout(timer);cleanup();reject(new DOMException('carrier closed','AbortError'))};
  const cleanup=()=>{lifecycleController.signal.removeEventListener('abort',abort);if(external)external.removeEventListener('abort',abort)};
  lifecycleController.signal.addEventListener('abort',abort,{once:true});if(external)external.addEventListener('abort',abort,{once:true});
  timer=setTimeout(()=>{cleanup();resolve()},milliseconds);
 });
}
const options=(method,token,body,headers,signal,keepalive)=>({
 method,body,signal,keepalive:!!keepalive,mode:'same-origin',credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',
 headers:Object.assign(token?{Authorization:'Bearer '+token}:{},body?{'Content-Type':'application/octet-stream'}:{},headers||{})
});
function splitFrames(value){
 const view=new DataView(value),result=[];let offset=0;
 while(offset<value.byteLength){
  if(value.byteLength-offset<8||result.length>=maxFrames)throw new Error('invalid frame batch');
  const type=view.getUint8(offset),id=view.getUint32(offset)&0x00ffffff,size=view.getUint32(offset+4),end=offset+8+size;
  if((type===2&&!size)||size>maxPayload||end>value.byteLength)throw new Error('invalid frame');
  result.push({type,id,data:offset===0&&end===value.byteLength?value:value.slice(offset,end)});offset=end;
 }
 if(!result.length)throw new Error('empty frame batch');
 return result;
}
function frameBound(value,frameLimit,byteLimit){
 const view=new DataView(value);let offset=0,frames=0;
 while(offset<value.byteLength){
  if(value.byteLength-offset<8)throw new Error('invalid frame batch');
  const size=view.getUint32(offset+4),end=offset+8+size;
  if(size>maxPayload||end>value.byteLength)throw new Error('invalid frame');
  if(frames&&(frames>=frameLimit||end>byteLimit))break;
  frames++;offset=end;
 }
 return {frames,bytes:offset};
}
function reserve(data){
 if(!data.byteLength||data.byteLength>queueByteLimit-queuedBytes||queuedItems>=queueItemLimit)return false;
 queuedBytes+=data.byteLength;queuedItems++;return true;
}
function release(bytes,items){queuedBytes-=bytes;queuedItems-=items}
function joinPending(values){
 let total=0,count=0,frames=0;
 while(count<values.length){
  const bound=frameBound(values[count],maxFrames,batchLimit),whole=bound.bytes===values[count].byteLength;
  if(!count&&!whole){
   const head=new Uint8Array(values[0],0,bound.bytes).slice();values[0]=values[0].slice(bound.bytes);queuedItems++;
   return {body:head.buffer,total:bound.bytes,count:1};
  }
  if(count&&(total+values[count].byteLength>batchLimit||frames+bound.frames>maxFrames))break;
  total+=values[count].byteLength;frames+=bound.frames;count++;
 }
 const joined=new Uint8Array(total);let offset=0;
 for(const data of values.splice(0,count)){joined.set(new Uint8Array(data),offset);offset+=data.byteLength}
 return {body:joined.buffer,total,count};
}
function retryAfterMs(response){
 const value=response.headers.get('Retry-After');if(!value)return 0;
 const seconds=Number(value);if(Number.isFinite(seconds)&&seconds>=0)return Math.min(seconds*1000,30000);
 const when=Date.parse(value);return Number.isFinite(when)&&when>Date.now()?Math.min(when-Date.now(),30000):0;
}
async function request(path,makeOptions){
 let delay=250,attempt=0;const deadline=Date.now()+90000;
 while(true){
  ensureOpen();const requestOptions=makeOptions(),controller=new AbortController(),external=requestOptions.signal;
  ensureOpen(external);const remaining=deadline-Date.now();if(remaining<=0)throw new Error('carrier retry deadline reached');
  const abort=()=>controller.abort();lifecycleController.signal.addEventListener('abort',abort,{once:true});if(external)external.addEventListener('abort',abort,{once:true});requestOptions.signal=controller.signal;
  ensureOpen(external);
  const timer=setTimeout(abort,remaining);let retry=0,unavailable=false;
  try{
   const response=await fetch(relayOrigin+path,requestOptions);
   if(response.status!==503)return response;
   unavailable=true;retry=retryAfterMs(response);await response.arrayBuffer();
  }catch(error){ensureOpen(external);if(++attempt===9)throw new Error('carrier retry limit reached')}
  finally{clearTimeout(timer);lifecycleController.signal.removeEventListener('abort',abort);if(external)external.removeEventListener('abort',abort)}
  ensureOpen(external);const backoffRemaining=deadline-Date.now();if(backoffRemaining<=0)throw new Error('carrier retry deadline reached');
  status('reconnecting');const backoff=Math.min(retry||(delay+Math.floor(Math.random()*Math.max(1,delay/4))),backoffRemaining);await pause(backoff,external);if(!unavailable)delay=Math.min(delay*2,5000);
 }
}
function fail(){if(closed)return;status('failed');if(port)port.postMessage({t:'close'});close(true)}
async function createSession(first){
 try{
  status('connecting');
  const response=await request('/api/v1/session',()=>options('POST',bootstrap,first));
  if(response.status!==200||response.headers.get('X-Carrier-Mode')!==carrier)throw new Error('session creation rejected');
  sessionToken=response.headers.get('X-Session-Token')||'';downCursor=response.headers.get('X-Down-Cursor')||'0';
  const welcome=await response.arrayBuffer();
  if(!sessionToken||welcome.byteLength!==8||new DataView(welcome).getUint8(0)!==17)throw new Error('invalid session creation');
  if(closed){deleteSession();return}port.postMessage(welcome,[welcome]);status('connected');
  if(carrier==='https-lanes')ensureLane(0);
  for(const data of beforeSession.splice(0)){release(data.byteLength,1);queueCarrier(data)}
  if(carrier==='https')poll();else pollLane(lanes.get(0));
 }catch(error){fail()}
}
function queueCarrier(data){
 try{if(carrier==='https')queueUp(data);else for(const frame of splitFrames(data))queueLane(frame)}catch(error){fail()}
}
function queueUp(data){
 try{splitFrames(data)}catch(error){fail();return}
 if(!reserve(data)){fail();return}upPending.push(data);runUp();
}
async function runUp(){
 if(upRunning)return;upRunning=true;
 try{
  while(!closed&&sessionToken&&upPending.length){
   const batch=joinPending(upPending),sequence=String(upSequence);
   const response=await request('/api/v1/up',()=>options('POST',sessionToken,batch.body,{'X-Up-Seq':sequence}));
   if(response.status!==204||response.headers.get('X-Up-Ack')!==sequence)throw new Error('uplink rejected');
   release(batch.total,batch.count);port.postMessage({t:'traffic',up:batch.total,down:0});upSequence++;
  }
 }catch(error){fail()}finally{upRunning=false;if(!closed&&sessionToken&&upPending.length)runUp()}
}
async function poll(){
 while(!closed&&sessionToken){
  try{
   pollController=new AbortController();
   const response=await request('/api/v1/down',()=>options('POST',sessionToken,null,{'X-Down-Cursor':downCursor},pollController.signal));
   if(response.status===204){status('connected');continue}
   if(response.status!==200)throw new Error('downlink rejected');
   const next=response.headers.get('X-Down-Cursor')||'',data=await response.arrayBuffer(),frames=splitFrames(data);
   if(!next||!frames.length)throw new Error('invalid downlink response');
   if(closed)return;port.postMessage({t:'traffic',up:0,down:data.byteLength});port.postMessage(data,[data]);downCursor=next;status('connected');
  }catch(error){if(!closed)fail();return}
 }
}
function ensureLane(id){
 let lane=lanes.get(id);
 if(!lane){lane={id,sequence:1,cursor:'0',pending:[],running:false,polling:false,controller:null};lanes.set(id,lane)}
 return lane;
}
function rememberLaneClosed(id){
 if(!id||closedLanes.has(id))return;
 if(closedLaneOrder.length===closedLaneLimit)closedLanes.delete(closedLaneOrder.shift());
 closedLanes.add(id);closedLaneOrder.push(id);
}
function finishLane(lane){
 if(!lane||lanes.get(lane.id)!==lane)return;
 for(const data of lane.pending)release(data.byteLength,1);
 lane.pending.length=0;lanes.delete(lane.id);rememberLaneClosed(lane.id);
}
function queueLane(frame){
 let lane=lanes.get(frame.id);
 if(!lane&&(frame.type===2||frame.type===3||frame.type===4))return;
 if(!lane&&closedLanes.has(frame.id))throw new Error('closed lane was reused');
 if(!lane&&frame.type!==1)throw new Error('lane did not begin with OPEN');
 lane=lane||ensureLane(frame.id);
 if(!reserve(frame.data)){fail();return}
 lane.pending.push(frame.data);runLaneUp(lane);
}
async function runLaneUp(lane){
 if(lane.running)return;lane.running=true;
 try{
  while(!closed&&sessionToken&&lane.pending.length){
   const batch=joinPending(lane.pending),sequence=String(lane.sequence),laneID=String(lane.id);
   const response=await request('/api/v1/up',()=>options('POST',sessionToken,batch.body,{'X-Up-Seq':sequence,'X-Lane-ID':laneID}));
   if(response.status!==204||response.headers.get('X-Up-Ack')!==sequence)throw new Error('lane uplink rejected');
   release(batch.total,batch.count);port.postMessage({t:'traffic',up:batch.total,down:0});lane.sequence++;
   if(!lane.polling)pollLane(lane);
  }
 }catch(error){fail()}finally{lane.running=false;if(!closed&&sessionToken&&lane.pending.length)runLaneUp(lane)}
}
async function pollLane(lane){
 if(!lane||lane.polling)return;lane.polling=true;
 try{
  while(!closed&&sessionToken&&lanes.get(lane.id)===lane){
   const controller=new AbortController(),laneID=String(lane.id);lane.controller=controller;
   const response=await request('/api/v1/down',()=>options('POST',sessionToken,null,{'X-Down-Cursor':lane.cursor,'X-Lane-ID':laneID},controller.signal));
   if(response.status===204){if(response.headers.get('X-Lane-Closed')==='1'){finishLane(lane);return}status('connected');continue}
   if(response.status!==200)throw new Error('lane downlink rejected');
   const next=response.headers.get('X-Down-Cursor')||'',data=await response.arrayBuffer(),frames=splitFrames(data);
   if(!next||!frames.length)throw new Error('invalid lane downlink response');
   for(const frame of frames)if(frame.id!==lane.id)throw new Error('cross-lane frame');
   if(closed)return;port.postMessage({t:'traffic',up:0,down:data.byteLength});port.postMessage(data,[data]);lane.cursor=next;status('connected');
  }
 }catch(error){if(!closed)fail()}finally{lane.polling=false;lane.controller=null}
}
function deleteSession(){if(sessionToken)fetch(relayOrigin+'/api/v1/session',options('DELETE',sessionToken,null,null,undefined,true)).catch(()=>{})}
function close(notifyServer){
 if(closed)return;closed=true;lifecycleController.abort();if(pollController)pollController.abort();
 for(const lane of lanes.values())if(lane.controller)lane.controller.abort();
 if(notifyServer)deleteSession();beforeSession.length=0;upPending.length=0;
 for(const lane of lanes.values())lane.pending.length=0;lanes.clear();queuedBytes=0;queuedItems=0;if(port)port.close();
}
function activatePort(nextPort){
 initialized=true;port=nextPort;
 port.onmessage=message=>{
  if(message.data instanceof ArrayBuffer){
   if(!createStarted){if(message.data.byteLength>64){fail();return}createStarted=true;createSession(message.data)}
   else if(!sessionToken){try{splitFrames(message.data)}catch(error){fail();return}if(!reserve(message.data)){fail();return}beforeSession.push(message.data)}
   else queueCarrier(message.data);
  }else if(message.data&&message.data.t==='close')close(true);
 };
 port.start();status('connecting');
}
addEventListener('message',event=>{
 if(initialized||event.source!==parent||!event.data||typeof event.data!=='object')return;
 const keys=Object.keys(event.data).sort();
 if(keys.length!==2||keys[0]!=='t'||keys[1]!=='v'||event.data.t!=='tproxy-init'||event.data.v!==1||event.ports.length!==1)return;
 let source;try{source=new URL(event.origin)}catch(error){return}
 if(source.protocol!=='http:'||source.hostname!=='127.0.0.1'||!source.port||source.origin!==event.origin)return;
 activatePort(event.ports[0]);
});
const androidBridge=globalThis.TelegramWebProxy;
if(!initialized&&androidNonce&&androidBridge&&typeof androidBridge.postMessage==='function'){
 const androidPort={onmessage:null,start(){},close(){androidBridge.onmessage=null},postMessage(value){
  if(value instanceof ArrayBuffer){let frames;try{frames=splitFrames(value)}catch(error){fail();return}for(const frame of frames)androidBridge.postMessage(frame.data)}
  else androidBridge.postMessage(JSON.stringify(value));
 }};
 androidBridge.onmessage=event=>{let data=event.data;if(typeof data==='string'){try{data=JSON.parse(data)}catch(error){return}}if(androidPort.onmessage)androidPort.onmessage({data})};
 activatePort(androidPort);androidBridge.postMessage(JSON.stringify({t:'tproxy-android-init',v:1,nonce:androidNonce}));
}
addEventListener('pagehide',()=>close(true),{once:true});
})();
</script>
</body>
</html>
`
