/* Genuine Chromium acceptance test. Requires Playwright + installed Chromium.
 * Start TRACE with --retain-capture-for-inspection, then run:
 * node scripts/validation/browser_mentor_demo.cjs http://127.0.0.1:8765 mentor-demo.pcap
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
  const browser = await chromium.launch({headless:true});
  try {
    const page = await browser.newPage({viewport:{width:1440,height:1000}});
    const errors=[],remote=[];
    page.on('pageerror', error=>errors.push(error.message));
    page.on('request', request=>{if(!request.url().startsWith(base+'/'))remote.push(request.url());});
    await page.goto(base);
    await page.waitForFunction(()=>document.getElementById('mode').textContent==='RULES-ONLY SELECTED');
    await page.locator('#file').setInputFiles(capture);
    await page.waitForFunction(()=>!document.getElementById('export').disabled);
    await page.getByRole('button',{name:/PII findings/}).click();
    await page.locator('#findings-body tr').filter({hasText:'a***@example.invalid'}).first().getByRole('button',{name:/Inspect/}).click();
    await page.locator('#conversation-sources button').filter({hasText:'frame_5'}).waitFor();
    assert.match(await page.locator('#selected-finding').innerText(),/EMAIL/);
    await page.locator('#conversation-sources button').filter({hasText:'frame_5'}).click();
    assert.match(await page.locator('#conversation-packet').innerText(),/Original file bytes/);
    await page.getByRole('button',{name:'Response · HTTP/1.1 200',exact:true}).click();
    await page.locator('.source-disclosure summary').click();
    await page.getByLabel('I am authorised to view this response and understand it may contain sensitive values.').check();
    await page.getByRole('button',{name:'Reveal response source',exact:true}).click();
    await page.waitForFunction(()=>document.getElementById('conversation-content').textContent.includes('<script>'));
    assert.equal(await page.locator('#conversation-content script, #conversation-content img').count(),0);
    assert.equal(await page.evaluate(()=>window.TRACE_UNTRUSTED_EXECUTED),undefined);
    assert.deepEqual(remote,[]);
    await page.getByRole('button',{name:'Hide source',exact:true}).click();
    assert.equal(await page.locator('#conversation-content').textContent(),'');
    await page.getByRole('button',{name:/Request · POST/}).press('Enter');
    await page.waitForFunction(()=>document.getElementById('conversation-status').textContent.includes('Request:'));
    assert.deepEqual(errors,[]);
    await page.setViewportSize({width:390,height:844});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1),true);
    console.log(JSON.stringify({browser:'Chromium',status:'passed',checks:['upload','finding selection','packet navigation','response source','no active HTML','no remote fetch','keyboard','small screen']}));
  } finally { await browser.close(); }
})().catch(error=>{console.error(error.message);process.exitCode=1;});
