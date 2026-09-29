// A replacement session starts empty. Telegram receives CLOSE for each retired
// stream and opens new streams; no DATA crosses a session boundary.
let epoch=0,epochController=new AbortController(),recovering=false,hello=null,welcomed=false;
let recoveryTimer=0,recoveryWall=0,recoveryMono=0,lastActivity=Date.now();
const recoveryBudget=15000,activeStreams=new Set();
const current=value=>!closed&&value===epoch;
const monotonic=()=>performance.now();
function recoveryRemaining(){
 return Math.max(0,Math.min(recoveryBudget-(Date.now()-recoveryWall),recoveryBudget-(monotonic()-recoveryMono)));
}
function transportError(message){return Object.assign(new Error(message),{recoverable:true})}
function canRecover(reason,error){
 return welcomed&&hello&&bridgeCapability&&(reason==='ws_closed'||reason==='ws_open'||reason==='ws_lane_open'||
  error&&error.recoverable);
}
function streamClose(id){
 const data=new ArrayBuffer(8);new DataView(data).setUint32(0,0x03000000|id);return data;
}
function visitFrames(data,visit){
 const view=new DataView(data);let offset=0,count=0;
 while(offset<data.byteLength){
  if(data.byteLength-offset<8||++count>maxFrames)throw new Error('invalid frame batch');
  const type=view.getUint8(offset),id=view.getUint32(offset)&0xffffff,size=view.getUint32(offset+4),end=offset+8+size;
  if(type===2&&!size||size>maxPayload||end>data.byteLength)throw new Error('invalid frame');
  visit(type,id,offset,end);offset=end;
 }
 if(!count)throw new Error('empty frame batch');
}
function acceptNative(data){
 let skipped=null;
 visitFrames(data,(type,id,start,end)=>{
  if(closedLanes.has(id)){
   if(type===1){const close=streamClose(id);port.postMessage(close,[close])}
   if(!skipped)skipped=[];skipped.push([start,end]);return;
  }
  if(type===1){
   if(activeStreams.size>=streamLimit&&!activeStreams.has(id))throw new Error('stream limit reached');
   activeStreams.add(id);
  }else if(type===3)activeStreams.delete(id);
 });
 lastActivity=Date.now();
 if(!skipped)return data;
 const bytes=data.byteLength-skipped.reduce((total,[start,end])=>total+end-start,0),result=new Uint8Array(bytes);let offset=0,previous=0;
 for(const [start,end] of skipped){result.set(new Uint8Array(data,previous,start-previous),offset);offset+=start-previous;previous=end}
 result.set(new Uint8Array(data,previous),offset);
 return result.buffer;
}
function deliver(data){
 visitFrames(data,(type,id)=>{if(type===3)activeStreams.delete(id)});
 lastActivity=Date.now();port.postMessage({t:'traffic',up:0,down:data.byteLength});port.postMessage(data,[data]);
}
function retireCarrier(){
 epoch++;epochController.abort();epochController=new AbortController();
 if(pollController)pollController.abort();pollController=null;
 for(const lane of lanes.values()){
  lane.finished=true;
  if(lane.controller)lane.controller.abort();
  if(lane.openController)lane.openController.abort();
  if(lane.timer)clearTimeout(lane.timer);
  if(lane.socket)try{lane.socket.close()}catch(error){}
  lane.pending.length=0;
 }
 if(carrier==='websocket'||carrier==='websocket-lanes'){
  if(webSocketTimer)clearTimeout(webSocketTimer);
  if(webSocket)try{webSocket.close()}catch(error){}
  webSocket=null;webSocketTimer=0;webSocketBufferedBytes=0;webSocketTrackedBytes=0;webSocketLaneReservations=0;
 }
 lanes.clear();upPending.length=0;beforeSession.length=0;queuedBytes=0;queuedItems=0;
 upRunning=false;upSequence=1;downCursor='0';
}
function beginRecovery(){
 if(closed||recovering)return;
 recovering=true;recoveryWall=Date.now();recoveryMono=monotonic();
 const previous=sessionToken;retireCarrier();sessionToken='';status('reconnecting');
 const retired=[...activeStreams];activeStreams.clear();
 for(const id of retired)rememberLaneClosed(id);
 for(const id of retired){const close=streamClose(id);port.postMessage(close,[close])}
 recoveryTimer=setTimeout(()=>{recoveryTimer=0;if(recovering&&!closed)terminalFailure('recovery_timeout')},recoveryBudget);
 recoverSession(previous).catch(()=>{if(!closed)terminalFailure('recovery_failed')});
}
async function recoverSession(previous){
 let delay=250;
 while(!closed&&recovering){
  if(recoveryRemaining()<=0)throw new Error('recovery deadline reached');
  try{
   const response=await request('/?bridge='+bridgeCapability,()=>options('GET',previous,null,{Accept:'application/vnd.telego.web-recovery+json'}));
   if(response.status!==200||response.headers.get('Content-Type')!=='application/vnd.telego.web-recovery+json')throw new Error('recovery rejected');
   const config=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(response.body));
   if(config.version!==1||typeof config.bootstrap!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(config.bootstrap)||
    config.carrier!==carrier||config.batch!==batchLimit||config.streams!==streamLimit)throw new Error('recovery policy changed');
   bootstrap=config.bootstrap;
   await createSession(hello.slice(0),true);
   return;
  }catch(error){
   if(closed||!recovering||!error.recoverable)throw error;
   if(recoveryRemaining()<=0)throw new Error('recovery deadline reached');
   if(sessionToken){previous=sessionToken;sessionToken=''}
   // Fence a failed replacement socket before retrying within this deadline.
   epoch++;epochController.abort();epochController=new AbortController();
   if(carrier==='websocket'&&webSocket){try{webSocket.close()}catch(error){}webSocket=null}
   await pause(Math.min(delay,recoveryRemaining()),epochController.signal);delay=Math.min(delay*2,2000);
  }
 }
}
function recoveryComplete(){
 if(!recovering)return;
 if(recoveryRemaining()<=0)throw new Error('recovery deadline reached');
 recovering=false;if(recoveryTimer)clearTimeout(recoveryTimer);recoveryTimer=0;
}
function wake(){
 if(!closed&&welcomed&&!recovering&&Date.now()-lastActivity>=30000)beginRecovery();
}
addEventListener('online',wake);
if(typeof document!=='undefined')document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible')wake()});
