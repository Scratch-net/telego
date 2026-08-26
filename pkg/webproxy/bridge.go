package webproxy

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
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
	return renderBridgeForCarrier(
		hostname,
		bootstrapToken,
		batchBytes,
		carrier,
		DefaultLimits().MaxStreamsPerSession,
	)
}

func renderBridgeForCarrier(
	hostname string,
	bootstrapToken string,
	batchBytes int,
	carrier CarrierMode,
	maxStreamsPerSession int,
) (BridgePage, error) {
	relayOrigin, webSocketOrigin, err := bridgeOrigins(hostname)
	if err != nil {
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
	if maxStreamsPerSession <= 0 {
		return BridgePage{}, errors.New("WEB bridge stream limit is out of range")
	}
	document := bridgeDocument
	if carrier.usesWebSocket() {
		document, err = bridgeDocumentWithWebSocket()
		if err != nil {
			return BridgePage{}, err
		}
	}

	var rawNonce [18]byte
	if _, err := rand.Read(rawNonce[:]); err != nil {
		return BridgePage{}, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(rawNonce[:])
	originJSON, _ := json.Marshal(relayOrigin)
	webSocketTargetJSON, _ := json.Marshal(webSocketOrigin + webSocketPath)
	tokenJSON, _ := json.Marshal(bootstrapToken)
	carrierJSON, _ := json.Marshal(carrier)
	body := strings.NewReplacer(
		"__NONCE__", nonce,
		"__ORIGIN__", string(originJSON),
		"__BOOTSTRAP__", string(tokenJSON),
		"__CARRIER__", string(carrierJSON),
		"__BATCH_LIMIT__", strconv.Itoa(batchBytes),
		"__MAX_STREAMS__", strconv.Itoa(maxStreamsPerSession),
		"__WEBSOCKET_TARGET__", string(webSocketTargetJSON),
	).Replace(document)
	if strings.Contains(body, "__NONCE__") || strings.Contains(body, "__ORIGIN__") ||
		strings.Contains(body, "__BOOTSTRAP__") || strings.Contains(body, "__CARRIER__") ||
		strings.Contains(body, "__BATCH_LIMIT__") || strings.Contains(body, "__MAX_STREAMS__") ||
		strings.Contains(body, "__WEBSOCKET_TARGET__") {
		return BridgePage{}, errors.New("WEB bridge template replacement failed")
	}
	connectSource := "connect-src 'self'"
	if carrier.usesWebSocket() {
		connectSource += " " + webSocketOrigin
	}

	return BridgePage{
		Body:  []byte(body),
		Nonce: nonce,
		CSP: strings.Join([]string{
			"default-src 'none'",
			"base-uri 'none'",
			"child-src 'none'",
			connectSource,
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

func bridgeOrigins(authority string) (relayOrigin, webSocketOrigin string, err error) {
	parsed, parseErr := url.Parse("https://" + authority)
	if parseErr != nil || parsed.Host != authority || parsed.User != nil || parsed.Path != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", ErrInvalidHostname
	}
	hostname := parsed.Hostname()
	if hostname == "" {
		return "", "", ErrInvalidHostname
	}
	hostPart := hostname
	if address, addressErr := netip.ParseAddr(hostname); addressErr == nil {
		if address.Zone() != "" || address.String() != hostname {
			return "", "", ErrInvalidHostname
		}
		if address.Is6() {
			hostPart = "[" + hostname + "]"
		}
	} else if validateErr := ValidateHostname(hostname); validateErr != nil {
		return "", "", validateErr
	}
	port := parsed.Port()
	if port != "" {
		parsedPort, portErr := strconv.ParseUint(port, 10, 16)
		if portErr != nil || parsedPort == 0 || strconv.FormatUint(parsedPort, 10) != port {
			return "", "", ErrInvalidHostname
		}
		hostPart += ":" + port
	}
	if hostPart != authority {
		return "", "", ErrInvalidHostname
	}
	return "https://" + authority, "wss://" + authority, nil
}

func bridgeDocumentWithWebSocket() (string, error) {
	document := bridgeDocument
	replacements := [...][2]string{
		{
			"let queuedBytes=0,queuedItems=0,upSequence=1,downCursor='0',upRunning=false,pollController=null;",
			"let queuedBytes=0,queuedItems=0,upSequence=1,downCursor='0',upRunning=false,pollController=null,webSocket=null,webSocketTimer=0,webSocketBufferedBytes=0,webSocketTrackedBytes=0,webSocketLaneReservations=0;",
		},
		{
			"const queueByteLimit=33554432,queueItemLimit=16384,maxFrames=4096,maxPayload=1048576,closedLaneLimit=4096;",
			"const queueByteLimit=33554432,queueItemLimit=16384,maxFrames=4096,maxPayload=1048576,closedLaneLimit=4096,laneQueueLimit=8388608,laneItemLimit=1024,maxWebSocketLanes=__MAX_STREAMS__;\nconst webSocketTarget=__WEBSOCKET_TARGET__;",
		},
		{
			`function reserve(data){
 if(!data.byteLength||data.byteLength>queueByteLimit-queuedBytes||queuedItems>=queueItemLimit)return false;
 queuedBytes+=data.byteLength;queuedItems++;return true;
}
function release(bytes,items){queuedBytes-=bytes;queuedItems-=items}`,
			`function refreshWebSocketBuffered(socket,lane){
 const current=socket?socket.bufferedAmount:0,previous=lane?lane.buffered:webSocketTrackedBytes;
 webSocketBufferedBytes+=current-previous;if(lane)lane.buffered=current;else webSocketTrackedBytes=current;
}
function bufferedBytes(lane){
 if(carrier==='websocket')refreshWebSocketBuffered(webSocket,null);else if(lane)refreshWebSocketBuffered(lane.socket,lane);
 return webSocketBufferedBytes;
}
function refreshAllWebSocketBuffered(){
 if(carrier==='websocket')refreshWebSocketBuffered(webSocket,null);else for(const activeLane of lanes.values())refreshWebSocketBuffered(activeLane.socket,activeLane);
 return webSocketBufferedBytes;
}
function hasWebSocketByteCapacity(data,lane){
 if(queuedBytes+bufferedBytes(lane)<=queueByteLimit-data.byteLength)return true;
 return queuedBytes+refreshAllWebSocketBuffered()<=queueByteLimit-data.byteLength;
}
function reserve(data,lane){
 if(!data.byteLength||queuedItems>=queueItemLimit)return false;
 if(lane&&(lane.bytes>laneQueueLimit-data.byteLength||lane.items>=laneItemLimit))return false;
 if(!hasWebSocketByteCapacity(data,lane))return false;
 queuedBytes+=data.byteLength;queuedItems++;if(lane){lane.bytes+=data.byteLength;lane.items++}return true;
}
function release(bytes,items,lane){queuedBytes-=bytes;queuedItems-=items;if(lane){lane.bytes-=bytes;lane.items-=items}}`,
		},
		{"function joinPending(values){", "function joinPending(values,lane){"},
		{"values[0]=values[0].slice(bound.bytes);queuedItems++;", "values[0]=values[0].slice(bound.bytes);queuedItems++;if(lane)lane.items++;"},
		{
			"if(closed){deleteSession();return}port.postMessage(welcome,[welcome]);status('connected');",
			"if(carrier==='websocket')await openWebSocket();\n  if(closed){deleteSession();return}port.postMessage(welcome,[welcome]);status('connected');",
		},
		{
			"if(carrier==='https')poll();else pollLane(lanes.get(0));",
			"if(carrier==='https')poll();else if(carrier==='https-lanes')pollLane(lanes.get(0));",
		},
		{
			"try{if(carrier==='https')queueUp(data);else for(const frame of splitFrames(data))queueLane(frame)}catch(error){fail()}",
			"try{\n  if(carrier==='https')queueUp(data);\n  else if(carrier==='https-lanes')for(const frame of splitFrames(data))queueLane(frame);\n  else if(carrier==='websocket')queueWebSocket(data);\n  else for(const frame of splitFrames(data))queueWebSocketLane(frame);\n }catch(error){fail()}",
		},
		{
			"lane={id,sequence:1,cursor:'0',pending:[],running:false,polling:false,controller:null};",
			"lane={id,sequence:1,cursor:'0',pending:[],running:false,polling:false,controller:null,bytes:0,items:0,buffered:0,socket:null,timer:0,opened:false,localClosed:false,remoteClosed:false,finished:false};",
		},
		{"function deleteSession(){", webSocketBridgeFunctions + "\nfunction deleteSession(){"},
		{
			`function close(notifyServer){
 if(closed)return;closed=true;lifecycleController.abort();if(pollController)pollController.abort();
 for(const lane of lanes.values())if(lane.controller)lane.controller.abort();
 if(notifyServer)deleteSession();beforeSession.length=0;upPending.length=0;
 for(const lane of lanes.values())lane.pending.length=0;lanes.clear();queuedBytes=0;queuedItems=0;if(port)port.close();
}`,
			`function close(notifyServer){
 if(closed)return;closed=true;lifecycleController.abort();if(pollController)pollController.abort();
 for(const lane of lanes.values()){
  if(lane.controller)lane.controller.abort();if(lane.timer)clearTimeout(lane.timer);
  if(lane.socket)try{lane.socket.close()}catch(error){}
 }
 if(webSocketTimer)clearTimeout(webSocketTimer);if(webSocket)try{webSocket.close()}catch(error){}
 if(notifyServer)deleteSession();beforeSession.length=0;upPending.length=0;
 for(const lane of lanes.values())lane.pending.length=0;lanes.clear();queuedBytes=0;queuedItems=0;if(port)port.close();
}`,
		},
	}
	for _, replacement := range replacements {
		if strings.Count(document, replacement[0]) != 1 {
			return "", errors.New("WEB WebSocket bridge template section is not unique")
		}
		document = strings.Replace(document, replacement[0], replacement[1], 1)
	}
	return document, nil
}

const webSocketBridgeFunctions = `function openWebSocket(){
 return new Promise((resolve,reject)=>{
  const socket=new WebSocket(webSocketTarget,'tproxy-v1.'+sessionToken);webSocket=socket;socket.binaryType='arraybuffer';
  socket.onopen=()=>resolve();
  socket.onmessage=event=>{
   if(!(event.data instanceof ArrayBuffer)||!event.data.byteLength){fail();return}
   port.postMessage({t:'traffic',up:0,down:event.data.byteLength});port.postMessage(event.data,[event.data]);status('connected');
  };
  socket.onerror=()=>reject(new Error('websocket failed'));socket.onclose=()=>{if(!closed)fail()};
 });
}
function queueWebSocket(data){
 if(!reserve(data)){fail();return}upPending.push(data);runWebSocketUp();
}
function scheduleWebSocketUp(){
 if(!webSocketTimer)webSocketTimer=setTimeout(()=>{webSocketTimer=0;runWebSocketUp()},10);
}
function runWebSocketUp(){
 if(closed||!webSocket||webSocket.readyState!==WebSocket.OPEN)return;
 refreshWebSocketBuffered(webSocket,null);if(!upPending.length){if(webSocket.bufferedAmount)scheduleWebSocketUp();return}
 if(webSocket.bufferedAmount+queuedBytes>queueByteLimit||webSocket.bufferedAmount>=batchLimit){
  scheduleWebSocketUp();return;
 }
 try{
  const batch=joinPending(upPending);webSocket.send(batch.body);refreshWebSocketBuffered(webSocket,null);release(batch.total,batch.count);
  port.postMessage({t:'traffic',up:batch.total,down:0});if(upPending.length)queueMicrotask(runWebSocketUp);else if(webSocket.bufferedAmount)scheduleWebSocketUp();
 }catch(error){fail()}
}
function closeFrame(id){
 const data=new ArrayBuffer(8),view=new DataView(data);
 view.setUint8(0,3);view.setUint8(1,id>>>16);view.setUint8(2,id>>>8);view.setUint8(3,id);view.setUint32(4,0);return data;
}
function finishWebSocketLane(lane,notify){
 if(lane.finished||lanes.get(lane.id)!==lane)return;
 lane.finished=true;if(lane.timer)clearTimeout(lane.timer);
 webSocketBufferedBytes-=lane.buffered;lane.buffered=0;webSocketLaneReservations--;
 if(lane.bytes||lane.items)release(lane.bytes,lane.items,lane);
 lane.pending.length=0;lanes.delete(lane.id);rememberLaneClosed(lane.id);
 if(lane.socket&&(lane.socket.readyState===WebSocket.OPEN||lane.socket.readyState===WebSocket.CONNECTING))try{lane.socket.close()}catch(error){}
 if(notify&&port&&!closed){const frame=closeFrame(lane.id);port.postMessage(frame,[frame])}
}
function openWebSocketLane(lane){
 const socket=new WebSocket(webSocketTarget,'tproxy-lane-v1.'+sessionToken+'.'+lane.id);
 lane.socket=socket;socket.binaryType='arraybuffer';
 socket.onopen=()=>{if(closed||lane.finished){socket.close();return}lane.opened=true;status('connected');runWebSocketLaneUp(lane)};
 socket.onmessage=event=>{
  if(!(event.data instanceof ArrayBuffer)||!event.data.byteLength){fail();return}
  let frames;try{frames=splitFrames(event.data)}catch(error){fail();return}
  if(frames.some(frame=>frame.id!==lane.id)){fail();return}if(frames.some(frame=>frame.type===3))lane.remoteClosed=true;
  port.postMessage({t:'traffic',up:0,down:event.data.byteLength});port.postMessage(event.data,[event.data]);status('connected');
 };
 socket.onerror=()=>{};
 socket.onclose=()=>{
  if(closed||lane.finished)return;if(!lane.opened){fail();return}
  finishWebSocketLane(lane,!lane.localClosed&&!lane.remoteClosed);
 };
}
function queueWebSocketLane(frame){
 let lane=lanes.get(frame.id);
 if(!lane&&(frame.type===2||frame.type===3||frame.type===4))return;
 if(!frame.id||(!lane&&closedLanes.has(frame.id)))throw new Error('closed lane was reused');
 if(!lane&&frame.type!==1)throw new Error('lane did not begin with OPEN');
 if(!lane&&webSocketLaneReservations>=maxWebSocketLanes){fail();return}
 if(!lane){webSocketLaneReservations++;lane=ensureLane(frame.id)}if(!reserve(frame.data,lane)){fail();return}
 lane.pending.push(frame.data);if(frame.type===3)lane.localClosed=true;
 if(!lane.socket)openWebSocketLane(lane);else runWebSocketLaneUp(lane);
}
function scheduleWebSocketLaneUp(lane){
 if(!lane.timer)lane.timer=setTimeout(()=>{lane.timer=0;runWebSocketLaneUp(lane)},10);
}
function runWebSocketLaneUp(lane){
 const socket=lane.socket;
 if(closed||lane.finished||!socket||socket.readyState!==WebSocket.OPEN)return;
 refreshWebSocketBuffered(socket,lane);if(!lane.pending.length){if(socket.bufferedAmount)scheduleWebSocketLaneUp(lane);return}
 if(socket.bufferedAmount>=batchLimit){
  scheduleWebSocketLaneUp(lane);return;
 }
 try{
  const batch=joinPending(lane.pending,lane);socket.send(batch.body);refreshWebSocketBuffered(socket,lane);release(batch.total,batch.count,lane);
  port.postMessage({t:'traffic',up:batch.total,down:0});if(lane.pending.length)queueMicrotask(()=>runWebSocketLaneUp(lane));else if(socket.bufferedAmount)scheduleWebSocketLaneUp(lane);
 }catch(error){fail()}
}
`

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
