/* Genuine Chromium acceptance test. Requires Playwright + installed Chromium.
 * Start TRACE with --retain-capture-for-inspection, then run:
 * node scripts/validation/browser_mentor_demo.cjs http://127.0.0.1:8765 mentor-demo.pcap
 * Set CHROMIUM=/path/to/chrome to use a specific browser binary.
 * This uses a fresh browser context and fictional capture only.
 */
'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const {chromium} = require(require.resolve('playwright', {paths:[process.cwd(),process.env.CODEX_PRIMARY_RUNTIME_NODE_MODULES||process.cwd()]}));
const base = process.argv[2] || 'http://127.0.0.1:8765';
const capture = path.resolve(process.argv[3] || 'mentor-demo.pcap');
if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(base)) throw Error('Use the local-only test server');
(async()=>{
  const browser = await chromium.launch({headless:true, ...(process.env.CHROMIUM?{executablePath:process.env.CHROMIUM,args:['--no-sandbox']}:{})});
  try {
    const page = await browser.newPage({viewport:{width:1440,height:1000}});
    const errors=[],remote=[];
    page.on('pageerror', error=>errors.push(error.message));
    page.on('request', request=>{if(!request.url().startsWith(base+'/'))remote.push(request.url());});
    await page.goto(base);
    await page.waitForFunction(()=>document.getElementById('mode').textContent==='Rules only');
    await page.locator('#file').setInputFiles(capture);
    await page.waitForFunction(()=>!document.getElementById('export').disabled);
    await page.locator('.nav-link[data-tab=findings]').click();
    // Inspect opens beside the list; the page does not move.
    const before = await page.evaluate(()=>scrollY);
    await page.locator('#findings-body tr').filter({hasText:'a***@example.invalid'}).first().locator('.row-main').click();
    await page.locator('#fi-support .msg-card').waitFor();
    assert.equal(await page.evaluate(()=>scrollY), before);
    assert.match(await page.locator('#inspect-title').innerText(),/Email/);
    // Follow the evidence to the HTTP message and its packets.
    await page.locator('#fi-support .msg-card .btn').click();
    await page.locator('#insp-dynamic .x-table').filter({hasText:'frame_5'}).waitFor();
    await page.locator('#insp-dynamic .x-table button').filter({hasText:'frame_5'}).click();
    assert.match(await page.locator('#insp-dynamic .x-table').innerText(),/Within frame/);
    // The response half of the same conversation, then opt-in source.
    await page.locator('#insp-dynamic .switch-btn').filter({hasText:/^Response/}).click();
    await page.getByLabel('I am authorised to view this response and understand it may contain sensitive values.').check();
    await page.getByRole('button',{name:'Show response source',exact:true}).click();
    await page.waitForFunction(()=>(document.querySelector('.src-code')||{}).textContent?.includes('<script>'));
    assert.equal(await page.locator('#inspector script, #inspector img').count(),0);
    assert.equal(await page.evaluate(()=>window.TRACE_UNTRUSTED_EXECUTED),undefined);
    assert.deepEqual(remote,[]);
    await page.getByRole('button',{name:'Hide source',exact:true}).click();
    assert.equal(await page.locator('.src-code').count(),0);
    // Back returns to the finding; the keyboard reaches the request.
    await page.locator('#insp-back').click();
    await page.locator('#insp-finding:not(.hidden)').waitFor();
    await page.locator('#fi-support .msg-card .btn').click();
    await page.locator('#insp-dynamic .switch-btn').filter({hasText:/^Request/}).press('Enter');
    await page.waitForFunction(()=>document.getElementById('insp-kicker').textContent==='HTTP request');
    assert.deepEqual(errors,[]);
    await page.setViewportSize({width:390,height:844});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1),true);
    console.log(JSON.stringify({browser:'Chromium',status:'passed',checks:['upload','inspect in place','packet navigation','response source','no active HTML','no remote fetch','keyboard','small screen']}));
  } finally { await browser.close(); }
})().catch(error=>{console.error(error.message);process.exitCode=1;});
