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
    const otp=document.querySelector('#code');otp.scrollIntoView({block:'center'});otp.focus();
    assert(!UI_FIXTURE.calls.some(x=>x.command==='getTotpCode'),'OTP secrets not fetched on passive focus');
    document.querySelector('.vela-field-icon').dispatchEvent(new MouseEvent('mousedown',{bubbles:true}));await pause(40);
    assert(document.querySelector('.vela-code-readout [aria-label="284619"]'),'OTP chooser shows native response');
    click('.vela-dd-item');assert(otp.value==='284619'&&!document.querySelector('.vela-inline-dropdown'),'OTP fills and closes');
    const card=document.querySelector('#card');card.scrollIntoView({block:'center'});
    card.dispatchEvent(new MouseEvent('mouseover',{bubbles:true}));
    const hoveredIcon=document.querySelector('.vela-field-icon');
    hoveredIcon.querySelector('svg').dispatchEvent(new MouseEvent('mousedown',{bubbles:true,cancelable:true,composed:true}));
    assert(hoveredIcon.isConnected,'hovered icon survives the focus caused by its press');
    card.focus();
    assert(!UI_FIXTURE.calls.some(x=>x.command==='getCards'&&x.userInitiated!==false),'full cards not fetched on passive focus');
    await pause(30);assert(document.querySelector('[data-vela-card-id=visa]'),'card suggestions open on focus');
    const opened=document.querySelector('.vela-inline-dropdown');
    const glyph=document.querySelector('.vela-field-icon svg path') || document.querySelector('.vela-field-icon svg');
    for(const type of ['mousedown','mouseup','click'])glyph.dispatchEvent(new MouseEvent(type,{bubbles:true,composed:true,cancelable:true}));
    await pause(250);assert(document.querySelector('.vela-inline-dropdown')===opened,'nested icon click keeps focus chooser open');
    document.querySelector('.vela-field-icon').dispatchEvent(new MouseEvent('mousedown',{bubbles:true}));await pause(30);
    const master=document.querySelector('[data-vela-card-id=master]');master.dispatchEvent(new MouseEvent('mouseenter'));
    assert(master.classList.contains('vela-dd-item--selected'),'hover updates selection');master.click();await pause(30);
    assert(card.value==='5555555555555556'&&document.querySelector('#cvv').value==='456','whole selected card fills');
    const first=document.querySelector('#first');first.scrollIntoView({block:'center'});first.focus();
    assert(!UI_FIXTURE.calls.some(x=>x.command==='getIdentities'&&x.userInitiated!==false),'full identities not fetched on passive focus');
    await pause(30);assert(document.querySelectorAll('[data-identity-index]').length===2,'identity suggestions open on focus');
    document.querySelector('.vela-field-icon').dispatchEvent(new MouseEvent('mousedown',{bubbles:true}));await pause(40);
    assert(document.querySelectorAll('[data-identity-index]').length===2,'identity chooser offers each address');
    click('[data-identity-index="1"]');await pause(30);
    assert(first.value==='Ada'&&document.querySelector('#last').value==='Lovelace','identity names filled');
    assert(document.querySelector('#street').value==='42 Engine Street'&&document.querySelector('#city').value==='Oxford','selected address filled');
    assert(document.querySelector('#country').value==='GB'&&document.querySelector('#contact-email').value==='ada@example.test','identity contact and country select filled');
    assert(!document.querySelector('#hidden-name').value,'hidden identity fields remain empty');
    const pan=document.querySelector('#split-number');pan.scrollIntoView({block:'center'});pan.focus();
    document.querySelector('.vela-field-icon').dispatchEvent(new MouseEvent('mousedown',{bubbles:true}));await pause(40);click('[data-vela-card-id=visa]');await pause(30);
    assert(document.querySelector('#month').value==='8'&&document.querySelector('#year').value==='2029'&&document.querySelector('#secret-cvv').value==='123','split expiry selects and password CVV filled');
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
