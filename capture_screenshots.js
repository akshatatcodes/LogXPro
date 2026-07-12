/**
 * LogXPro – Real Screenshot Capture Script
 * Run: node capture_screenshots.js
 * Requires: npm install puppeteer (installed inline via npx)
 */

const puppeteer = require('puppeteer')
const path      = require('path')
const fs        = require('fs')

const BASE  = 'http://localhost:3000'
const OUT   = path.join(__dirname, 'docs', 'screenshots')

const PAGES = [
  { name: 'dashboard',         url: '/',                   wait: 3000, width: 1600, height: 900 },
  { name: 'alert_queue',       url: '/alerts',             wait: 3000, width: 1600, height: 900 },
  { name: 'log_analysis',      url: '/logs',               wait: 3000, width: 1600, height: 900 },
  { name: 'cases',             url: '/cases',              wait: 2500, width: 1600, height: 900 },
  { name: 'file_upload',       url: '/upload',             wait: 2000, width: 1600, height: 900 },
  { name: 'guide',             url: '/guide',              wait: 2000, width: 1600, height: 900 },
]

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)) }

;(async () => {
  if (!fs.existsSync(OUT)) fs.mkdirSync(OUT, { recursive: true })

  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-web-security', '--window-size=1600,900'],
    defaultViewport: null,
  })

  const page = await browser.newPage()
  await page.setViewport({ width: 1600, height: 900, deviceScaleFactor: 1.5 })

  for (const p of PAGES) {
    try {
      console.log(`📸 Capturing: ${p.name} → ${BASE}${p.url}`)
      await page.goto(`${BASE}${p.url}`, { waitUntil: 'networkidle2', timeout: 15000 })
      await sleep(p.wait)

      // For alert queue: expand the first row to show attack chain
      if (p.name === 'alert_queue') {
        try {
          await page.click('tbody tr:first-child')
          await sleep(1500)
        } catch (_) {}
      }

      const outPath = path.join(OUT, `${p.name}.png`)
      await page.screenshot({ path: outPath, type: 'png' })
      console.log(`   ✅ Saved → ${outPath}`)
    } catch (err) {
      console.error(`   ❌ Failed ${p.name}: ${err.message}`)
    }
  }

  // Special: attack chain modal screenshot
  try {
    console.log(`📸 Capturing: attack_chain_modal`)
    await page.goto(`${BASE}/alerts`, { waitUntil: 'networkidle2', timeout: 15000 })
    await sleep(3000)
    // Click the ⬡ chain graph button on first row
    const chainBtn = await page.$('button[title="Open Attack Chain View"]')
    if (chainBtn) {
      await chainBtn.click()
      await sleep(2000)
      const outPath = path.join(OUT, 'attack_chain.png')
      await page.screenshot({ path: outPath, type: 'png' })
      console.log(`   ✅ Saved → ${outPath}`)
    }
  } catch (err) {
    console.error(`   ❌ Failed attack_chain: ${err.message}`)
  }

  await browser.close()
  console.log('\n🎉 All screenshots captured!')
})()
