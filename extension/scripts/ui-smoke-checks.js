/* Run in the local fixture's console: await runVelaUiChecks().
 * Exercises production scripts against the synthetic bridge, never a real vault.
 */
async function runVelaUiChecks() {
  if (!window.UI_FIXTURE) throw new Error('Open the isolated ui-preview-server fixture first.');
  const passed=[];
  const assert=(ok,label)=>{if(!ok)throw new Error(label);passed.push(label);};
  const click=selector=>{const el=document.querySelector(selector);assert(!!el,'control exists: '+selector);el.click();};
  const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
  if (document.querySelector('#navSite')) {
    assert(Math.abs(document.documentElement.getBoundingClientRect().width-380)<1&&Math.abs(document.body.getBoundingClientRect().width-380)<1,'popup root and body retain the intended intrinsic width');
    click('#navSearch');const input=document.querySelector('#loginSearch');input.value='studio';input.dispatchEvent(new Event('input',{bubbles:true}));
    assert(document.querySelectorAll('.login-item').length===1,'search filters native account data');
    click('[data-action=copy-username]');await pause(10);
    assert(UI_FIXTURE.calls.some(x=>x.command==='clipboard'&&x.text==='alex@studio.example'),'copy uses selected username');
    click('#navGenerate');const range=document.querySelector('#genLength');range.value=32;range.dispatchEvent(new Event('input',{bubbles:true}));
    assert(document.querySelector('#genOutput').textContent.length===32,'password length changes');
    click('#genModePassphrase');assert(document.querySelector('#genOutput').textContent.includes('-'),'passphrase generation stays available');
    click('#navMore');const theme=document.querySelector('#instrumentTheme');theme.value='macchiato';theme.dispatchEvent(new Event('change',{bubbles:true}));await pause(10);
    assert(document.documentElement.dataset.velaTheme==='macchiato'&&UI_FIXTURE.store.velaInstrumentTheme==='macchiato','theme persists');
    for(const view of ['site','search','generate','more']){click('button[data-view='+view+']');assert(document.body.scrollWidth<=document.body.clientWidth,'no horizontal overflow: '+view);}
    click('#navSite');
    click('[data-item-type=card]');await pause(30);
    assert(document.querySelectorAll('[data-fill-item]').length===2,'popup lists saved cards');
    assert(!document.querySelector('#mainContent').textContent.includes('4242424242424242'),'popup masks card numbers');
    click('[data-fill-item]');await pause(30);
    assert(UI_FIXTURE.calls.some(x=>x.command==='fillVaultItem'&&x.itemType==='card'&&x.itemId==='visa'),'popup fills card by native ID');
    click('[data-item-type=identity]');await pause(30);
    assert(document.querySelectorAll('[data-fill-item]').length===2,'popup offers each identity address');
    click('[data-fill-item="1"]');await pause(30);
    assert(UI_FIXTURE.calls.some(x=>x.command==='fillVaultItem'&&x.itemType==='identity'&&x.addressId==='office'),'popup preserves selected address');
    click('[data-item-type=login]');await pause(30);
  } else {
    // Console-created events are deliberately untrusted: they must never
    // open a chooser or release credentials. Test real fills using browser
    // automation clicks/keys, rather than weakening the production guard.
    for (const id of ['card', 'first']) {
      const field = document.getElementById(id);
      const before = UI_FIXTURE.calls.filter(x => ['getCards','getIdentities'].includes(x.command)).length;
      field.scrollIntoView({block:'center'}); field.focus(); await pause(30);
      assert(!document.querySelector('[data-vela-card-id], [data-identity-index]'),'focus alone does not publish global vault metadata: '+id);
      const icon = document.querySelector('.vela-field-icon');
      icon.dispatchEvent(new MouseEvent('mousedown',{bubbles:true,cancelable:true}));
      field.dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowDown',bubbles:true}));
      await pause(30);
      assert(UI_FIXTURE.calls.filter(x => ['getCards','getIdentities'].includes(x.command)).length === before,'scripted focus/icon/key cannot request cards or identities: '+id);
    }
    await UI_FIXTURE.dispatch({command:'showSaveDialog',username:'new@example.test',password:'EXAMPLE-ONLY'});
    assert(document.querySelector('#vela-save-modal [role=dialog]'),'save review is a dialog');
    click('#vela-save-modal [data-vela-action=save]');await pause(30);
    assert(UI_FIXTURE.calls.some(x=>x.command==='saveCredentials'),'review uses native save command');
    document.querySelector('#username').value='new@example.test';document.querySelector('#password').value='EXAMPLE-ONLY-new';
    document.querySelector('#login').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));await pause(180);
    click('[data-vela-action=never]');assert(!UI_FIXTURE.store.velaNeverSaveDomains,'never-save does not persist before confirmation');
    click('[data-confirm]');await pause(30);assert(UI_FIXTURE.store.velaNeverSaveDomains?.includes('localhost'),'never-save persists after confirmation');
    const target=document.querySelector('#new-password');target.scrollIntoView({block:'center'});target.focus();
    document.querySelector('.vela-field-icon--gen').dispatchEvent(new MouseEvent('mousedown',{bubbles:true}));await pause(30);
    assert(!document.querySelector('.vela-inline-dropdown'),'generator hides pending chooser');
    const length=document.querySelector('#vela-gen-length');length.value=32;length.dispatchEvent(new Event('input',{bubbles:true}));const generated=document.querySelector('#vela-gen-preview').textContent;
    click('#vela-gen-modal [data-vela-action=use]');assert(target.value===generated&&generated.length===32,'generated password fills source field');
  }
  assert(UI_FIXTURE.errors.length===0,'no browser exceptions');
  return passed;
}
