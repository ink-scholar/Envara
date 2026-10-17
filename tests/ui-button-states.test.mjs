import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { _electron } from 'playwright-core';

// Exercise the actual CSS cascade in an owned renderer, without Envara IPC,
// services, saved user data or a frontend build.
const noDisplay = process.platform === 'linux' && !process.env.DISPLAY;
const classes = ['button', 'button primary', 'button danger', 'icon-button',
  'terminal-icon-button', 'terminal-text-button', 'terminal-text-button terminal-start-button',
  'terminal-empty-start', 'terminal-close-session', 'terminal-duplicate-session',
  'terminal-text-button terminal-account-delete'];
let fixture, desktop, page;

before(async () => {
  if (noDisplay) return;
  fixture = await mkdtemp(path.join(tmpdir(), 'envara-button-states-'));
  const css = await Promise.all(['styles.css', 'terminal.css'].map(name => readFile(new URL(`../src/${name}`, import.meta.url), 'utf8')));
  const html = `<style>${css.join('\n')}</style><div style="display:flex;gap:12px;padding:40px;flex-wrap:wrap">${classes.map((name, i) => `<button id="control-${i}" class="${name}">Action</button>`).join('')}</div>`;
  const entry = path.join(fixture, 'main.cjs');
  await writeFile(entry, `const { app, BrowserWindow } = require('electron');
app.setPath('userData', ${JSON.stringify(path.join(fixture, 'data'))});
app.whenReady().then(() => { app.dock?.hide(); const window = new BrowserWindow({ show: false, width: 1440, height: 600, webPreferences: { sandbox: true } }); window.loadURL(${JSON.stringify(`data:text/html;charset=utf-8,${encodeURIComponent(html)}`)}); });`);
  const env = { ...process.env };
  delete env.ELECTRON_RUN_AS_NODE;
  desktop = await _electron.launch({ args: [entry], env, timeout: 15000 });
  page = await desktop.firstWindow();
  await page.locator('#control-0').waitFor();
  // Remove timing from state assertions; reduced-motion has its own check below.
  await page.emulateMedia({ reducedMotion: 'reduce' });
});

after(async () => {
  await desktop?.close();
  if (fixture) await rm(fixture, { recursive: true, force: true });
});

const style = locator => locator.evaluate(element => {
  const css = getComputedStyle(element), box = element.getBoundingClientRect();
  return { surface: [css.backgroundColor, css.borderStyle === 'none' ? null : css.borderColor, css.color], cursor: css.cursor,
    opacity: Number(css.opacity), outline: css.outlineStyle, outlineWidth: css.outlineWidth,
    transition: css.transitionDuration, box: [box.x, box.y, box.width, box.height] };
});

test('action buttons give hover and press feedback without moving their hit targets', { skip: noDisplay }, async () => {
  for (let i = 0; i < classes.length; i++) {
    const control = page.locator(`#control-${i}`);
    await page.mouse.move(5, 5);
    const rest = await style(control);
    await control.hover();
    const hover = await style(control);
    assert.notDeepEqual(hover.surface, rest.surface, `${classes[i]} has hover feedback`);
    await page.mouse.down();
    const pressed = await style(control);
    await page.mouse.up();
    assert.notDeepEqual(pressed.surface, hover.surface, `${classes[i]} has press feedback`);
    assert.deepEqual(hover.box, rest.box, `${classes[i]} hover does not shift its target`);
    assert.deepEqual(pressed.box, rest.box, `${classes[i]} press does not shift its target`);
  }
});

test('disabled and busy buttons remain visually unavailable under the pointer', { skip: noDisplay }, async () => {
  for (let i = 0; i < classes.length; i++) {
    const control = page.locator(`#control-${i}`);
    await page.mouse.move(5, 5);
    const rest = await style(control);
    for (const attribute of ['disabled', 'aria-disabled', 'aria-busy']) {
      await control.evaluate((element, name) => element.setAttribute(name, 'true'), attribute);
      try {
        const box = await control.boundingBox();
        await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
        const unavailable = await style(control);
        assert.deepEqual(unavailable.surface, rest.surface, `${classes[i]} ${attribute} keeps its resting surface`);
        assert.equal(unavailable.cursor, attribute === 'aria-busy' ? 'progress' : 'default');
        assert.ok(unavailable.opacity < 1 && unavailable.opacity >= .4, 'unavailable labels remain readable');
      } finally {
        await control.evaluate((element, name) => element.removeAttribute(name), attribute);
        await page.mouse.move(5, 5);
      }
    }
  }
});

test('keyboard focus stays visible and reduced motion disables action transitions', { skip: noDisplay }, async () => {
  await page.keyboard.press('Tab');
  for (let i = 0; i < classes.length; i++) {
    const control = page.locator(`#control-${i}`);
    await control.focus();
    const focused = await style(control);
    assert.equal(focused.outline, 'solid', `${classes[i]} retains a keyboard focus ring`);
    assert.equal(focused.outlineWidth, '2px');
    assert.equal(focused.transition, '0s');
  }
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  const duration = (await style(page.locator('#control-0'))).transition.split(',').map(value => Number.parseFloat(value));
  assert.ok(duration.every(value => value > 0 && value <= .12), 'ordinary feedback stays brief');
});


test('terminal actions use the compact scale and wrap long labels without widening their container', { skip: noDisplay }, async () => {
  const result = await page.evaluate(() => {
    const host = document.createElement('div');
    host.style.cssText = 'width:190px;display:flex;flex-wrap:wrap';
    host.innerHTML = '<button class="terminal-text-button">Eine sehr lange übersetzte Terminalaktion</button>';
    document.body.append(host);
    const button = host.firstElementChild, css = getComputedStyle(button);
    const box = button.getBoundingClientRect(), outer = host.getBoundingClientRect();
    const value = { height: box.height, width: box.width, available: outer.width, fontSize: css.fontSize, radius: css.borderRadius, whiteSpace: css.whiteSpace };
    host.remove();
    return value;
  });
  assert.equal(result.fontSize, '12px');
  assert.equal(result.radius, '8px');
  assert.equal(result.whiteSpace, 'normal');
  assert.ok(result.height >= 30, 'compact actions retain a 30px minimum target');
  assert.ok(result.width <= result.available, 'translated labels wrap within their action group');
  for (const i of [4, 5, 6, 7, 8, 9, 10]) {
    const control = page.locator(`#control-${i}`);
    assert.ok((await control.boundingBox()).height >= 30, `${classes[i]} uses the compact minimum`);
  }
});

test('the terminal chooser stays inside its own dock and long session names retain a visible status', { skip: noDisplay }, async () => {
  const result = await page.evaluate(() => {
    const dock = document.createElement('section');
    dock.className = 'terminal-dock';
    dock.style.cssText = 'width:640px;height:320px';
    dock.innerHTML = `<div class="terminal-session-tabs"><button class="terminal-session-tab"><span class="terminal-session-name">${'Long named workspace '.repeat(12)}</span><small>Running</small></button></div><div class="terminal-new-session"><div>${'<p>Translated account configuration</p>'.repeat(20)}</div></div>`;
    document.body.append(dock);
    const chooser = dock.querySelector('.terminal-new-session'), tab = dock.querySelector('.terminal-session-tab');
    const name = dock.querySelector('.terminal-session-name'), status = dock.querySelector('small');
    const outer = dock.getBoundingClientRect(), popup = chooser.getBoundingClientRect();
    const value = { inside: popup.left >= outer.left && popup.right <= outer.right && popup.top >= outer.top && popup.bottom <= outer.bottom,
      scrollable: chooser.scrollHeight > chooser.clientHeight, overflowY: getComputedStyle(chooser).overflowY,
      tabWidth: tab.getBoundingClientRect().width, nameWidth: name.getBoundingClientRect().width, statusWidth: status.getBoundingClientRect().width,
      nameOverflow: getComputedStyle(name).textOverflow, statusShrink: getComputedStyle(status).flexShrink };
    dock.remove();
    return value;
  });
  assert.ok(result.inside, 'the chooser is positioned and bounded by its own dock');
  assert.ok(result.scrollable && result.overflowY === 'auto', 'long forms scroll within the available dock height');
  assert.ok(result.tabWidth <= 260 && result.nameWidth > 0 && result.statusWidth > 0, 'a single long name cannot consume the tab strip');
  assert.equal(result.nameOverflow, 'ellipsis');
  assert.equal(result.statusShrink, '0');
});
