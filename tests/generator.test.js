// Run with:  node tests/generator.test.js
const assert=require("assert");
const {secureRandomInt:r,generatePassword:g}=require("../script.js");
// 1. rejection sampling really re-rolls
const real=globalThis.crypto.getRandomValues.bind(globalThis.crypto);
const seq=[4294967295,4294967295,5]; let calls=0;
Object.defineProperty(globalThis,"crypto",{value:{getRandomValues:b=>{b[0]=seq[calls++];return b}},configurable:true});
assert.strictEqual(r(3),2); assert.strictEqual(calls,3);
Object.defineProperty(globalThis,"crypto",{value:{getRandomValues:real},configurable:true});
// 2. range + uniformity
const N=300000,cnt=[0,0,0,0,0,0,0];
for(let i=0;i<N;i++){const v=r(7);assert(v>=0&&v<7);cnt[v]++}
const exp=N/7,chi=cnt.reduce((s,c)=>s+(c-exp)**2/exp,0);
console.log("chi-square (6 dof, <16.8 ok at 1%):",chi.toFixed(2)); assert(chi<22.5);
for(const bad of [0,-1,1.5,NaN,2**32+1]) assert.throws(()=>r(bad));
assert.strictEqual(r(1),0);
// 3. generator
const sets={upper:/[A-Z]/,lower:/[a-z]/,numbers:/[0-9]/,symbols:/[^A-Za-z0-9]/};
for(let i=0;i<3000;i++){
  const o={length:12+(i%53),upper:!!(i&1),lower:!!(i&2),numbers:!!(i&4),symbols:!!(i&8)};
  if(!(o.upper||o.lower||o.numbers||o.symbols)){assert.throws(()=>g(o),/at least one/);continue}
  const p=g(o); assert.strictEqual(p.length,o.length);
  for(const k in sets) assert.strictEqual(sets[k].test(p),o[k],k+" "+p+" "+JSON.stringify(o));
}
for(let i=0;i<2000;i++){const p=g({length:12+(i%53),upper:true,lower:true,numbers:true,symbols:true,noDuplicates:true});assert.strictEqual(new Set(p).size,p.length)}
assert.throws(()=>g({length:12,numbers:true,noDuplicates:true}),/unique/);
assert.strictEqual(new Set(g({length:12,lower:true,numbers:true,noDuplicates:true})).size,12);
for(const L of [11,65,12.5,NaN,"16",undefined]) assert.throws(()=>g({length:L,lower:true}),/Length/);
assert.notStrictEqual(g({length:16,lower:true}),g({length:16,lower:true}));
// 4. position spread of first char (shuffle sanity)
const first=new Set();for(let i=0;i<200;i++)first.add(/[0-9]/.test(g({length:12,lower:true,numbers:true})[0]));
assert(first.size===2);
console.log("all generator tests passed");
