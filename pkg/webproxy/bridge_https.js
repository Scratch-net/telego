// Finite HTTP batches share an ordered uplink window and bounded replay buffers.
let httpWindow=1,downRetainedBytes=0;
const httpUp=newHTTPUp(),httpDown={transaction:null},downWaiters=new Set();
const maxSequence=18446744073709551615n;
function newHTTPUp(){return {sequence:1n,frontier:0n,completed:new Set(),active:new Map()}}
function launchHTTPUp(state,pending,lane){
 const generation=epoch;
 while(current(generation)&&sessionToken&&pending.length&&state.sequence<=state.frontier+BigInt(httpWindow)){
  if(state.sequence>maxSequence){fail(lane?'lane_up':'up_send',new Error('uplink rejected'),lane&&lane.id);return}
  const batch=joinPending(pending),sequence=state.sequence++,key=String(sequence);
  state.active.set(key,batch);
  const alive=()=>current(generation)&&(!lane||lanes.get(lane.id)===lane);
  const settle=()=>{
   // A retired lane still owns its active bodies until their requests settle.
   batch.body=null;
   if(state.active.get(key)!==batch)return;
   state.active.delete(key);if(current(generation))release(batch.total,batch.count);
  };
  const headers={'X-Up-Seq':key};if(lane)headers['X-Lane-ID']=String(lane.id);
  request('/api/v1/up',()=>options('POST',sessionToken,batch.body,headers)).then(response=>{
   settle();if(!alive())return;
   if(response.status!==204)throw diagnosticException(transportError(lane?'lane uplink rejected':'uplink rejected'),{httpStatus:response.status});
   if(response.headers.get('X-Up-Ack')!==key)throw new Error('uplink rejected');
   port.postMessage({t:'traffic',up:batch.total,down:0});
   state.completed.add(sequence);while(state.completed.delete(state.frontier+1n))state.frontier++;
   if(lane&&!lane.polling)pollLane(lane);
   launchHTTPUp(state,pending,lane);
  }).catch(error=>{settle();if(alive())fail(lane?'lane_up':'up_send',error,lane&&lane.id)});
 }
}
function releaseDown(state){
 const transaction=state&&state.transaction;if(!transaction)return;
 state.transaction=null;downRetainedBytes-=transaction.bytes.byteLength;
 for(const wake of [...downWaiters])wake();
}
async function reserveDown(size,signal){
 ensureOpen(signal);
 if(size>queueByteLimit)throw new Error('response body exceeds its limit');
 if(size<=queueByteLimit-downRetainedBytes){downRetainedBytes+=size;return}
 if(downWaiters.size>=streamLimit+1)throw new Error('response body exceeds its limit');
 await new Promise((resolve,reject)=>{
  const cleanup=()=>{downWaiters.delete(wake);signal.removeEventListener('abort',abort)};
  const abort=()=>{cleanup();reject(new DOMException('carrier closed','AbortError'))};
  const wake=()=>{if(signal.aborted){abort();return}if(size<=queueByteLimit-downRetainedBytes){cleanup();downRetainedBytes+=size;resolve()}};
  downWaiters.add(wake);signal.addEventListener('abort',abort,{once:true});wake();
 });
}
function validateDownFrame(view,offset,size,lane){
 const type=view.getUint8(offset),id=view.getUint32(offset)&0xffffff;
 if(lane&&id!==lane.id)throw new Error('cross-lane frame');
 if(type===2){if(!id||!size)throw new Error('invalid frame')}
 else if(type===3){if(!id||size)throw new Error('invalid frame')}
 else if(type===4){if(!id||size!==4||view.getUint32(offset+8)===0)throw new Error('invalid frame')}
 else if(type===5){if(id||size>64)throw new Error('invalid frame')}
 else if(type===31){if(id)throw new Error('invalid frame')}
 else throw new Error('invalid frame');
}
async function readDownlink(response,lane,signal,deadline){
 const state=lane?(lane.downState||(lane.downState={transaction:null})):httpDown,base=lane?lane.cursor:downCursor;
 const next=response.headers.get('X-Down-Cursor')||'';
 if(!/^[1-9][0-9]*$/.test(next)||BigInt(next)>maxSequence||BigInt(next)!==BigInt(base)+1n)throw new Error('invalid downlink response');
 const limit=Math.max(batchLimit,maxPayload+8),length=response.headers.get('Content-Length'),encoding=response.headers.get('Content-Encoding');
 let declared=null;
 if(length!==null&&(!encoding||encoding.toLowerCase()==='identity')){
  if(!/^[0-9]+$/.test(length))throw new Error('invalid response length');
  declared=Number(length);
  if(!Number.isSafeInteger(declared)||declared>limit||declared===0)throw new Error('response body exceeds its limit');
 }
 let owner=state.transaction;
 if(owner&&(owner.base!==base||owner.next!==next||(owner.declared!==null&&declared!==null&&owner.declared!==declared)))throw new Error('invalid downlink response');
 if(owner&&declared!==null){
  if(declared<owner.retained)throw new Error('invalid response length');
  owner.declared=declared;
 }
 if(!response.body)throw new Error('missing response body');
 if(!owner){
  const capacity=declared===null?limit:declared;await reserveDown(capacity,signal);
  try{ensureOpen(signal);owner={base,next,declared,bytes:new Uint8Array(capacity),retained:0,delivered:0};state.transaction=owner}
  catch(error){downRetainedBytes-=capacity;for(const wake of [...downWaiters])wake();throw error}
 }
 const bodyLimit=owner.declared===null?owner.bytes.byteLength:owner.declared;
 const reader=response.body.getReader();let position=0,offset=0,frames=0,chunks=0,complete=false;
 const cancel=()=>{try{reader.cancel().catch(()=>{})}catch(error){}};signal.addEventListener('abort',cancel,{once:true});
 try{
  while(true){
   ensureOpen(signal);if(Date.now()>=deadline)throw new Error('response deadline reached');
   const part=await reader.read();ensureOpen(signal);if(Date.now()>=deadline)throw new Error('response deadline reached');
   if(part.done)break;
   const bytes=part.value;
   if(!(bytes instanceof Uint8Array)||++chunks>65536||bytes.byteLength>bodyLimit-position)throw new Error('response body exceeds its limit');
   const overlap=Math.min(bytes.byteLength,Math.max(0,owner.retained-position));
   for(let i=0;i<overlap;i++)if(bytes[i]!==owner.bytes[position+i])throw new Error('invalid downlink response');
   owner.bytes.set(bytes,position);position+=bytes.byteLength;owner.retained=Math.max(owner.retained,position);
   const view=new DataView(owner.bytes.buffer);
   while(position-offset>=8){
    const size=view.getUint32(offset+4),end=offset+8+size;
    if(size>maxPayload||end>bodyLimit)throw new Error('invalid frame');
    if(end>position)break;
    if(++frames>maxFrames)throw new Error('invalid frame batch');
    if(frames>1&&end>batchLimit)throw new Error('response batch exceeds its limit');
    validateDownFrame(view,offset,size,lane);
    if(end>owner.delivered){
     if(offset!==owner.delivered)throw new Error('invalid downlink response');
     const frame=owner.bytes.slice(offset,end).buffer;deliver(frame);owner.delivered=end;
    }
    offset=end;
   }
  }
  if(owner.declared!==null&&position!==owner.declared)throw new Error('invalid response length');
  if(!frames||offset!==position||position<owner.retained)throw new Error('invalid frame batch');
  if(lane)lane.cursor=next;else downCursor=next;
  complete=true;releaseDown(state);return new ArrayBuffer(0);
 }finally{if(!complete)cancel();signal.removeEventListener('abort',cancel);reader.releaseLock()}
}
async function pollHTTPS(lane){
 if(lane&&lane.polling)return;if(lane)lane.polling=true;
 const generation=epoch;
 try{
  while(current(generation)&&sessionToken&&(!lane||lanes.get(lane.id)===lane)){
   const controller=new AbortController();if(lane)lane.controller=controller;else pollController=controller;
   const headers={'X-Down-Cursor':lane?lane.cursor:downCursor};if(lane)headers['X-Lane-ID']=String(lane.id);
   const response=await request('/api/v1/down',()=>options('POST',sessionToken,null,headers,controller.signal),null,
    (response,signal,deadline)=>readDownlink(response,lane,signal,deadline));
   if(!current(generation))return;
   if(response.status===204){
    const state=lane?lane.downState:httpDown;
    if(state&&state.transaction)throw new Error('invalid downlink response');
    const cursor=response.headers.get('X-Down-Cursor');
    if(cursor!==null&&cursor!==(lane?lane.cursor:downCursor))throw new Error('invalid downlink response');
    if(lane&&response.headers.get('X-Lane-Closed')==='1'){finishLane(lane);return}
   }else if(response.status!==200)throw diagnosticException(transportError(lane?'lane downlink rejected':'downlink rejected'),{httpStatus:response.status});
   status('connected');
  }
 }catch(error){if(current(generation))fail(lane?'lane_down':'down_poll',error,lane&&lane.id)}
 finally{if(lane){lane.polling=false;lane.controller=null}}
}
function resetHTTPS(){
 releaseDown(httpDown);for(const lane of lanes.values()){releaseDown(lane.downState);if(lane.upState)lane.upState.active.clear()}
 httpUp.active.clear();httpUp.completed.clear();httpUp.sequence=1n;httpUp.frontier=0n;httpWindow=1;
}
