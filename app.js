/* ======================================================
   Memorial Tree - Web App (free obituary builder)
   Single-file vanilla JS SPA. Persistence: Firestore.
   ====================================================== */

import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.14.1/firebase-app.js';
import {
  getFirestore, collection, onSnapshot,
  doc, setDoc, deleteDoc
} from 'https://www.gstatic.com/firebasejs/10.14.1/firebase-firestore.js';

const firebaseConfig = {
  apiKey: "AIzaSyBiTgTlFO99hgVXZ0MG_PKdEdlUP9s5iCY",
  authDomain: "memorialtree-6446e.firebaseapp.com",
  databaseURL: "https://memorialtree-6446e-default-rtdb.asia-southeast1.firebasedatabase.app",
  projectId: "memorialtree-6446e",
  storageBucket: "memorialtree-6446e.firebasestorage.app",
  messagingSenderId: "717119474073",
  appId: "1:717119474073:web:60fa0098fc24442f396b08"
};
const fbApp = initializeApp(firebaseConfig);
const db = getFirestore(fbApp);
const obitsCol = collection(db, 'obituaries');

(() => {
  'use strict';

  // ---------- Storage (Firestore for data, localStorage for photos) ----------
  const SESSION_KEY = 'mt.session.v1';
  const PHOTO_KEY = (id) => 'mt.photo.' + id;
  const getLocalPhoto = (id) => { try { return localStorage.getItem(PHOTO_KEY(id)) || ''; } catch { return ''; } };
  const setLocalPhoto = (id, dataUrl) => {
    try {
      if (dataUrl) localStorage.setItem(PHOTO_KEY(id), dataUrl);
      else localStorage.removeItem(PHOTO_KEY(id));
    } catch (e) { console.warn('localStorage photo write failed', e); }
  };
  const removeLocalPhoto = (id) => { try { localStorage.removeItem(PHOTO_KEY(id)); } catch {} };

  // ---------- Password hashing (SHA-256 + app pepper) ----------
  const HASH_PREFIX = 'h1:';
  const HASH_PEPPER = 'mt.v1.memorialtree.pepper';
  async function sha256Hex(s) {
    const buf = new TextEncoder().encode(s);
    const hash = await crypto.subtle.digest('SHA-256', buf);
    return HASH_PREFIX + Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
  }
  const hashPw = (pw) => sha256Hex(HASH_PEPPER + '|' + pw);
  const isHashed = (v) => typeof v === 'string' && v.startsWith(HASH_PREFIX);
  async function matchPw(stored, input) {
    if (!stored || input == null) return false;
    if (!isHashed(stored)) return stored === input;
    return stored === await hashPw(input);
  }

  const storage = {
    _cache: [],
    _ready: false,
    list() {
      return [...this._cache].sort((a, b) => (b.updatedAt || '').localeCompare(a.updatedAt || ''));
    },
    get(id) { return this._cache.find(o => o.id === id); },
    upsert(obit) {
      obit.updatedAt = new Date().toISOString();
      setLocalPhoto(obit.id, obit.deceased?.photo || '');
      const cached = JSON.parse(JSON.stringify(obit));
      if (cached.deceased) cached.deceased.photo = '';
      const idx = this._cache.findIndex(o => o.id === obit.id);
      if (idx >= 0) this._cache[idx] = cached; else this._cache.unshift(cached);
      (async () => {
        try {
          const plain = JSON.parse(JSON.stringify(obit));
          if (plain.deceased) plain.deceased.photo = '';
          if (plain.password && !isHashed(plain.password)) plain.password = await hashPw(plain.password);
          if (Array.isArray(plain.messages)) {
            for (const m of plain.messages) {
              if (m.password && !isHashed(m.password)) m.password = await hashPw(m.password);
            }
          }
          await setDoc(doc(obitsCol, obit.id), plain);
        } catch (e) {
          console.error('Firestore upsert failed', e);
          toast('저장 중 오류가 발생했습니다.');
        }
      })();
      return obit;
    },
    remove(id) {
      this._cache = this._cache.filter(o => o.id !== id);
      removeLocalPhoto(id);
      deleteDoc(doc(obitsCol, id)).catch((e) => {
        console.error('Firestore delete failed', e);
        toast('삭제 중 오류가 발생했습니다.');
      });
    }
  };

  onSnapshot(obitsCol, (snap) => {
    storage._cache = snap.docs.map(d => {
      const data = d.data();
      if (data.deceased) data.deceased.photo = getLocalPhoto(d.id);
      return data;
    });
    storage._ready = true;
    if (['landing', 'my', 'detail'].includes(state.route)) render();
  }, (err) => {
    console.error('Firestore subscribe failed', err);
    toast('데이터를 불러오지 못했습니다.');
  });

  const session = {
    get() { try { return JSON.parse(sessionStorage.getItem(SESSION_KEY)) || {}; } catch { return {}; } },
    set(s) { sessionStorage.setItem(SESSION_KEY, JSON.stringify(s)); },
    clear() { sessionStorage.removeItem(SESSION_KEY); }
  };

  // ---------- Utilities ----------
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const uid = () => 'o_' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
  const todayISO = () => new Date().toISOString().slice(0, 10);
  const fmtDate = (iso) => iso ? iso.replaceAll('-', '.') : '';
  const fmtDateTime = (iso) => {
    if (!iso) return '';
    const [d, t] = iso.split('T');
    return d.replaceAll('-', '.') + (t ? ' ' + t.slice(0, 5) : '');
  };
  const escapeHtml = (str = '') => String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

  function calcAge(birth, death) {
    if (!birth || !death) return '';
    const b = new Date(birth), d = new Date(death);
    if (isNaN(b) || isNaN(d)) return '';
    let age = d.getFullYear() - b.getFullYear();
    const m = d.getMonth() - b.getMonth();
    if (m < 0 || (m === 0 && d.getDate() < b.getDate())) age--;
    return age >= 0 ? `향년 ${age}세` : '';
  }
  function calcKoreanAge(birthYYMMDD) {
    if (!/^\d{6}$/.test(birthYYMMDD || '')) return null;
    const yy = +birthYYMMDD.slice(0, 2);
    const now = new Date().getFullYear();
    const nowYY = now % 100;
    const year = yy > nowYY ? 1900 + yy : 2000 + yy;
    return now - year + 1;
  }
  function ageDisplay(birthYYMMDD) {
    const a = calcKoreanAge(birthYYMMDD);
    return a != null ? `향년 ${a}세` : '';
  }
  // Render an <img> matching the editor's crop/scale/offset for a target box w×h
  function photoCropImgHTML(ph, w, h) {
    if (!ph?.photo) return '';
    const nw = ph.photoNW || 0, nh = ph.photoNH || 0;
    if (!nw || !nh) {
      return `<img src="${escapeHtml(ph.photo)}" alt="영정" style="width:100%;height:100%;object-fit:cover;display:block;">`;
    }
    const imgRatio = nw / nh;
    const cropRatio = w / h;
    let baseW, baseH;
    if (imgRatio > cropRatio) { baseH = h; baseW = h * imgRatio; }
    else { baseW = w; baseH = w / imgRatio; }
    const scale = ph.photoScale || 1;
    const ox = (ph.photoOffsetXRel || 0) * w;
    const oy = (ph.photoOffsetYRel || 0) * h;
    return `<img src="${escapeHtml(ph.photo)}" alt="영정" style="position:absolute;top:50%;left:50%;width:${baseW}px;height:${baseH}px;max-width:none;transform:translate(calc(-50% + ${ox}px), calc(-50% + ${oy}px)) scale(${scale});transform-origin:center;display:block;">`;
  }

  // ---------- Options (bottom-sheet data) ----------
  const SEX_OPTIONS = ['남', '여'];
  const RELATION_OPTIONS = ['미지정', '남편', '배우자(처)', '아들', '며느리', '딸', '사위', '손자', '손녀', '부모', '형제', '자매', '친척', '기타'];
  const BANK_OPTIONS = [
    'KB국민은행', '신한은행', '우리은행', 'NH농협은행', '하나은행',
    'IBK기업은행', 'SC제일은행', '카카오뱅크', '토스뱅크', '케이뱅크',
    '새마을금고', '우체국', '수협은행', '부산은행', '대구은행',
    '광주은행', '전북은행', '제주은행', '신협', '기타',
  ];

  // ---------- Model ----------
  function newObituary() {
    return {
      id: uid(),
      status: 'draft', // draft | published | ended
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      password: '',
      // 고인 정보
      deceased: {
        name: '', sex: '', birth: '', death: '',
        titles: [''], // 직함 목록 (첫 행은 항상 유지)
        photo: '', // dataURL
        photoBW: false,
        showPhoto: true, showTitle: true,
      },
      // 상주 (첫 행은 필수)
      mourners: [{ relation: '', name: '' }], // [{relation, name}]
      // 장례 일정
      funeral: {
        deathAt: '', // 별세일시
        encoffinAt: '',
        carryAt: '',
        place: '', // 장지
        funeralHome: '', // 빈소
        showAll: true,
      },
      // 알리는 글
      notice: '',
      // 마음을 전하는 곳 (계좌) - 첫 행은 대표 계좌(필수)
      donations: [{ relation: '', owner: '', bank: '', account: '' }], // [{relation, owner, bank, account}]
      noDonation: false, // 부조금을 받지 않겠습니다
      // 작성자 정보
      author: { name: '', phone: '', relation: '' },
      // 추모 메시지
      messagesEnabled: true,
      messages: [], // [{id, name, body, password, createdAt}]
    };
  }

  // ---------- App state ----------
  const state = {
    route: 'landing',
    params: {},
    draft: null, // current editing obituary
    activeObituaryId: null, // for menu actions
  };

  // ---------- Toast ----------
  const toastEl = $('#toast');
  let toastTimer;
  function toast(msg) {
    toastEl.textContent = msg;
    toastEl.classList.add('is-show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toastEl.classList.remove('is-show'), 2200);
  }

  // ---------- Modal ----------
  const modalEl = $('#modal'), modalPanel = $('#modalPanel');
  function openModal({ title, desc, body = '', actions = [] }) {
    return new Promise((resolve) => {
      modalPanel.innerHTML = `
        ${title ? `<div class="modal__title">${escapeHtml(title)}</div>` : ''}
        ${desc ? `<div class="modal__desc">${escapeHtml(desc)}</div>` : ''}
        ${body}
        <div class="modal__actions ${actions.length === 1 ? 'modal__actions--single' : ''}">
          ${actions.map((a, i) => `<button class="btn ${a.primary ? 'btn--primary' : 'btn--secondary'}" data-i="${i}">${escapeHtml(a.label)}</button>`).join('')}
        </div>
      `;
      modalEl.setAttribute('aria-hidden', 'false');
      modalPanel.querySelectorAll('button[data-i]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const i = +btn.dataset.i;
          const a = actions[i];
          const onClick = a.onClick;
          if (onClick) {
            const result = await onClick(modalPanel);
            if (result === false) return;
          }
          modalEl.setAttribute('aria-hidden', 'true');
          resolve(a.value !== undefined ? a.value : i);
        });
      });
    });
  }
  modalEl.querySelector('.modal__backdrop').addEventListener('click', () => modalEl.setAttribute('aria-hidden', 'true'));

  // ---------- Full popup ----------
  const fullPopup = document.getElementById('fullPopup');
  const fullPopupPanel = document.getElementById('fullPopupPanel');
  function openFullPopup(html) {
    fullPopupPanel.innerHTML = html;
    fullPopup.setAttribute('aria-hidden', 'false');
  }
  function closeFullPopup() { fullPopup.setAttribute('aria-hidden', 'true'); }

  // ---------- Bottom sheet ----------
  const sheetEl = $('#bottomSheet'), sheetPanel = $('#bottomSheetPanel');
  function openSheet(html) {
    sheetPanel.innerHTML = html;
    sheetEl.setAttribute('aria-hidden', 'false');
  }
  function closeSheet() { sheetEl.setAttribute('aria-hidden', 'true'); }
  $('#bottomSheetBackdrop').addEventListener('click', closeSheet);

  // My Obituaries auth bottom-sheet (phone + password)
  function openMyObituariesSheet() {
    openSheet(`
      <div class="sheet-head">
        <div class="sheet-title">나의 부고장 관리</div>
        <button class="sheet-close" id="myClose" aria-label="닫기">×</button>
      </div>
      <div class="field">
        <input class="input" type="tel" id="myPhone" placeholder="휴대폰 번호 *" inputmode="numeric" autocomplete="tel" maxlength="13" />
      </div>
      <div class="field">
        <input class="input" type="password" id="myPw" placeholder="비밀번호 6자리 *" inputmode="numeric" autocomplete="off" maxlength="6" />
        <div class="field__hint field__hint--error" id="myErr" hidden>일치하는 부고장이 없습니다.</div>
      </div>
      <div class="sheet-confirm">
        <button class="btn btn--primary btn--block" id="myConfirm" disabled>확인</button>
      </div>
    `);

    const phoneEl = $('#myPhone');
    const pwEl = $('#myPw');
    const errEl = $('#myErr');
    const confirmEl = $('#myConfirm');

    const formatPhone = (raw) => {
      const d = raw.replace(/\D/g, '').slice(0, 11);
      if (d.length < 4) return d;
      if (d.length < 8) return `${d.slice(0, 3)}-${d.slice(3)}`;
      return `${d.slice(0, 3)}-${d.slice(3, 7)}-${d.slice(7)}`;
    };
    const isPhoneValid = (v) => /^\d{3}-\d{3,4}-\d{4}$/.test(v);
    const updateState = () => {
      confirmEl.disabled = !(isPhoneValid(phoneEl.value) && pwEl.value.length === 6);
      errEl.hidden = true;
    };

    phoneEl.addEventListener('input', () => { phoneEl.value = formatPhone(phoneEl.value); updateState(); });
    pwEl.addEventListener('input', () => { pwEl.value = pwEl.value.replace(/\D/g, '').slice(0, 6); updateState(); });

    $('#myClose').addEventListener('click', closeSheet);
    confirmEl.addEventListener('click', async () => {
      if (confirmEl.disabled) return;
      const phone = phoneEl.value;
      const pw = pwEl.value;
      const normPhone = phone.replace(/\D/g, '');
      const candidates = storage.list().filter(o => (o.author?.phone || '').replace(/\D/g, '') === normPhone);
      let match = false;
      for (const o of candidates) {
        if (await matchPw(o.password, pw)) { match = true; break; }
      }
      if (!match) {
        errEl.hidden = false;
        toast('일치하는 부고장이 없습니다.');
        return;
      }
      closeSheet();
      navigate('my');
    });

    setTimeout(() => phoneEl.focus(), 50);
  }

  // Generic select-bottom-sheet
  function openSelectSheet({ title, options, value, layout = 'grid', onSelect }) {
    let selected = value ?? '';
    const optsHTML = () => layout === 'grid'
      ? `<div class="sheet-grid">${options.map(o => `
          <button type="button" class="sheet-grid__item ${o === selected || o.value === selected ? 'is-selected' : ''}" data-v="${escapeHtml(typeof o === 'string' ? o : o.value)}">
            ${escapeHtml(typeof o === 'string' ? o : o.label)}
          </button>`).join('')}</div>`
      : `<div class="sheet-list">${options.map(o => `
          <button type="button" class="sheet-list__item ${o === selected || o.value === selected ? 'is-selected' : ''}" data-v="${escapeHtml(typeof o === 'string' ? o : o.value)}">
            ${escapeHtml(typeof o === 'string' ? o : o.label)}
          </button>`).join('')}</div>`;
    openSheet(`
      <div class="sheet-head">
        <div class="sheet-title">${escapeHtml(title)}</div>
        <button class="sheet-close" id="ssClose" aria-label="닫기">×</button>
      </div>
      <div id="ssOptions">${optsHTML()}</div>
      <div class="sheet-confirm"><button class="btn btn--primary btn--block" id="ssConfirm" ${selected ? '' : 'disabled'}>선택 완료</button></div>
    `);
    const rebind = () => {
      sheetPanel.querySelectorAll('[data-v]').forEach(btn => btn.addEventListener('click', () => {
        selected = btn.dataset.v;
        sheetPanel.querySelector('#ssOptions').innerHTML = optsHTML();
        sheetPanel.querySelector('#ssConfirm').disabled = !selected;
        rebind();
      }));
    };
    rebind();
    $('#ssClose').addEventListener('click', closeSheet);
    $('#ssConfirm').addEventListener('click', () => {
      if (!selected) return;
      closeSheet();
      onSelect(selected);
    });
  }

  // ---------- Photo editor (full popup) ----------
  function openPhotoEditor(initial, onDone) {
    // local state
    let dataUrl = initial?.photo || '';
    let bw = !!initial?.bw;
    let scale = initial?.scale || 1;
    let offsetX = 0, offsetY = 0; // pixels for current crop area
    let initOffsetsApplied = false;
    const initRelX = +initial?.offsetXRel || 0;
    const initRelY = +initial?.offsetYRel || 0;

    const render = () => {
      openFullPopup(`
        <header class="fp-header fp-header--title-x">
          <div class="fp-header__title">영정 사진 추가</div>
          <button class="fp-header__close" id="fpClose" aria-label="닫기">×</button>
        </header>
        <div class="fp-body">
          ${dataUrl ? `
            <div class="photo-editor__stage ${bw ? 'is-bw' : ''}" id="peStage">
              <img id="peImg" src="${dataUrl}" alt="영정사진" />
              <div class="photo-editor__crop" id="peCrop">
                <div class="photo-editor__grid"></div>
              </div>
            </div>
            <div class="photo-editor__zoom">
              <span style="font-size:16px;color:var(--c-text-3);">−</span>
              <input id="peZoom" type="range" min="1" max="3" step="0.05" value="${scale}">
              <span style="font-size:16px;color:var(--c-text-3);">+</span>
            </div>
            <div class="photo-editor__bw">
              <span>흑백 모드</span>
              <span class="toggle ${bw ? 'is-on' : ''}" id="peBW"></span>
            </div>
          ` : `
            <div class="photo-editor__dropzone">
              <button class="photo-upload__btn" id="peAdd">+ 영정 사진 추가</button>
              <div class="hint">
                이미지 파일(jpg, png)만 등록하실 수 있습니다.<br>
                최대 20MB 까지 등록 가능합니다.
              </div>
            </div>
          `}
          <input type="file" id="peFile" accept="image/jpeg,image/png" hidden>
        </div>
        <div class="fp-footer">
          <button class="btn btn--secondary" id="peReselect" ${dataUrl ? '' : 'disabled'}>다시 선택</button>
          <button class="btn btn--primary" id="peDone" ${dataUrl ? '' : 'disabled'}>완료</button>
        </div>
      `);
      wire();
    };

    const wire = () => {
      const file = document.getElementById('peFile');
      const triggerFile = () => file.click();
      const addBtn = document.getElementById('peAdd');
      if (addBtn) addBtn.addEventListener('click', openCombobox);
      file.addEventListener('change', (e) => {
        const f = e.target.files?.[0];
        if (!f) return;
        if (f.size > 20 * 1024 * 1024) return toast('파일 크기는 20MB 이하만 가능합니다.');
        const reader = new FileReader();
        reader.onload = (ev) => {
          dataUrl = ev.target.result;
          scale = 1; offsetX = 0; offsetY = 0;
          // allow picking the same file next time
          e.target.value = '';
          render();
        };
        reader.readAsDataURL(f);
      });
      document.getElementById('fpClose')?.addEventListener('click', closeFullPopup);
      document.getElementById('peReselect')?.addEventListener('click', openCombobox);
      document.getElementById('peDone')?.addEventListener('click', () => {
        const cropEl = document.getElementById('peCrop');
        const r = cropEl ? cropEl.getBoundingClientRect() : { width: 0, height: 0 };
        const offsetXRel = r.width > 0 ? offsetX / r.width : 0;
        const offsetYRel = r.height > 0 ? offsetY / r.height : 0;
        const imgEl = document.getElementById('peImg');
        onDone({
          photo: dataUrl, bw, scale,
          offsetXRel, offsetYRel,
          nw: imgEl?.naturalWidth || 0,
          nh: imgEl?.naturalHeight || 0,
        });
        closeFullPopup();
      });
      const zoom = document.getElementById('peZoom');
      const img = document.getElementById('peImg');
      const stage = document.getElementById('peStage');
      if (zoom && img && stage) {
        const crop = document.getElementById('peCrop');
        const apply = () => {
          const r = crop.getBoundingClientRect();
          const iw = img.naturalWidth || 0;
          const ih = img.naturalHeight || 0;
          if (!iw || !ih || !r.width || !r.height) return;
          if (!initOffsetsApplied) {
            offsetX = initRelX * r.width;
            offsetY = initRelY * r.height;
            initOffsetsApplied = true;
          }
          const imgRatio = iw / ih;
          const cropRatio = r.width / r.height;
          let baseW, baseH;
          if (imgRatio > cropRatio) { baseH = r.height; baseW = r.height * imgRatio; }
          else { baseW = r.width; baseH = r.width / imgRatio; }
          img.style.width = baseW + 'px';
          img.style.height = baseH + 'px';
          const scaledW = baseW * scale;
          const scaledH = baseH * scale;
          const maxX = Math.max(0, (scaledW - r.width) / 2);
          const maxY = Math.max(0, (scaledH - r.height) / 2);
          offsetX = Math.max(-maxX, Math.min(maxX, offsetX));
          offsetY = Math.max(-maxY, Math.min(maxY, offsetY));
          img.style.transform = `translate(calc(-50% + ${offsetX}px), calc(-50% + ${offsetY}px)) scale(${scale})`;
        };
        if (img.complete && img.naturalWidth) apply();
        else img.addEventListener('load', apply, { once: true });
        zoom.addEventListener('input', () => { scale = +zoom.value; apply(); });

        // drag
        let dragging = false, startX = 0, startY = 0, startOX = 0, startOY = 0;
        stage.addEventListener('pointerdown', (e) => {
          dragging = true;
          startX = e.clientX; startY = e.clientY;
          startOX = offsetX; startOY = offsetY;
          stage.classList.add('is-dragging');
          try { stage.setPointerCapture(e.pointerId); } catch { }
        });
        stage.addEventListener('pointermove', (e) => {
          if (!dragging) return;
          offsetX = startOX + (e.clientX - startX);
          offsetY = startOY + (e.clientY - startY);
          apply();
        });
        const endDrag = (e) => {
          if (!dragging) return;
          dragging = false;
          stage.classList.remove('is-dragging');
          try { stage.releasePointerCapture(e.pointerId); } catch { }
        };
        stage.addEventListener('pointerup', endDrag);
        stage.addEventListener('pointercancel', endDrag);
        stage.addEventListener('pointerleave', endDrag);
      }
      const bwBtn = document.getElementById('peBW');
      if (bwBtn) bwBtn.addEventListener('click', () => {
        bw = !bw;
        bwBtn.classList.toggle('is-on', bw);
        document.getElementById('peStage').classList.toggle('is-bw', bw);
      });
    };

    const openCombobox = () => {
      openSheet(`
        <div class="sheet-head">
          <div class="sheet-title">영정 사진 추가</div>
          <button class="sheet-close" id="ssClose" aria-label="닫기">×</button>
        </div>
        <div class="photo-combobox">
          <button data-opt="library"><span>사진 보관함</span><span class="ico">🖼</span></button>
          <button data-opt="camera"><span>사진 찍기</span><span class="ico">📷</span></button>
          <button data-opt="file"><span>파일 선택</span><span class="ico">📁</span></button>
        </div>
      `);
      document.getElementById('ssClose').addEventListener('click', closeSheet);
      sheetPanel.querySelectorAll('[data-opt]').forEach(b => b.addEventListener('click', () => {
        closeSheet();
        const opt = b.dataset.opt;
        const file = document.getElementById('peFile');
        if (opt === 'camera') file.setAttribute('capture', 'environment');
        else file.removeAttribute('capture');
        file.click();
      }));
    };

    render();
  }

  // ---------- Slide menu ----------
  const slideMenu = $('#slideMenu');
  function isSlideMenuOpen() { return slideMenu.getAttribute('aria-hidden') === 'false'; }
  function openSlideMenu() {
    slideMenu.setAttribute('aria-hidden', 'false');
    $('#headerMenu').setAttribute('aria-expanded', 'true');
  }
  function closeSlideMenu() {
    slideMenu.setAttribute('aria-hidden', 'true');
    $('#headerMenu').setAttribute('aria-expanded', 'false');
  }
  $('#slideMenuClose').addEventListener('click', closeSlideMenu);
  $('#slideMenuBackdrop').addEventListener('click', closeSlideMenu);
  $('#headerMenu').addEventListener('click', openSlideMenu);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && isSlideMenuOpen()) closeSlideMenu(); });
  slideMenu.addEventListener('click', (e) => {
    const item = e.target.closest('[data-action]');
    if (!item) return;
    const action = item.dataset.action;
    closeSlideMenu();
    if (action === 'edit-obituary') {
      const id = state.activeObituaryId || $('#headerTitle').dataset.activeId;
      if (!id) return toast('수정할 부고장이 없습니다.');
      askPassword(id, () => navigate('edit', { id }));
    } else if (action === 'my-obituaries') {
      navigate('my');
    } else if (action === 'privacy') {
      navigate('privacy');
    } else if (action === 'terms') {
      navigate('terms');
    }
  });

  // ---------- Password gate ----------
  function askPassword(id, onOk) {
    const obit = storage.get(id);
    if (!obit) return toast('부고장을 찾을 수 없습니다.');
    openModal({
      title: '비밀번호 확인',
      desc: '부고장 작성 시 설정한 6자리 숫자를 입력해주세요.',
      body: `<div class="field"><input type="password" inputmode="numeric" maxlength="6" class="input" id="modalPw" placeholder="••••••" autocomplete="off"></div>`,
      actions: [
        { label: '취소' },
        {
          label: '확인', primary: true, onClick: async (panel) => {
            const v = panel.querySelector('#modalPw').value;
            if (!(await matchPw(obit.password, v))) {
              toast('비밀번호가 일치하지 않습니다.');
              return false;
            }
          }
        }
      ]
    }).then((res) => { if (res === 1) onOk(); });
  }

  // ---------- Routing ----------
  function navigate(route, params = {}) {
    state.route = route;
    state.params = params;
    render();
    window.scrollTo({ top: 0, behavior: 'instant' });
  }

  function setHeader({ title, back = false, menu = true, activeId = null }) {
    $('#headerTitle').innerHTML = title || `<span class="logo-mark">⚘</span> Memorial Tree`;
    $('#headerTitle').dataset.activeId = activeId || '';
    $('#headerBack').hidden = !back;
    $('#headerMenu').style.display = menu ? '' : 'none';
  }
  $('#headerBack').addEventListener('click', () => {
    // simple back logic
    if (state.route === 'create' || state.route === 'edit') {
      if (state.draft && hasUnsavedChanges()) {
        openModal({
          title: '작성 중인 내용이 있습니다.',
          desc: '화면을 벗어나면 작성 중인 내용이 사라집니다.',
          actions: [
            { label: '더보기' },
            { label: '벗어나기', primary: true, value: 'leave' },
          ]
        }).then((v) => { if (v === 'leave') { state.draft = null; navigate('landing'); } });
      } else { navigate('landing'); }
    } else if (state.route === 'preview') {
      navigate('create');
    } else if (state.route === 'detail') {
      navigate('landing');
    } else if (state.route === 'edit') {
      navigate('detail', { id: state.params.id });
    } else if (['my', 'privacy', 'terms', 'messages', 'message-write', 'ended'].includes(state.route)) {
      history.length > 1 ? history.back() : navigate('landing');
    } else {
      navigate('landing');
    }
  });

  function hasUnsavedChanges() {
    return state.draft && (state.draft.deceased?.name || state.draft.author?.name || state.draft.funeral?.deathAt);
  }

  // ---------- Renderer ----------
  const viewEl = $('#view');

  function render() {
    const r = state.route;
    if (r === 'landing') return renderLanding();
    if (r === 'my') return renderMyObituaries();
    if (r === 'create' || r === 'edit') return renderEditor();
    if (r === 'preview') return renderPreview();
    if (r === 'detail') return renderDetail();
    if (r === 'messages') return renderMessages();
    if (r === 'message-write') return renderMessageWrite();
    if (r === 'ended') return renderEnded();
    if (r === 'privacy') return renderPolicy('개인정보처리방침');
    if (r === 'terms') return renderPolicy('서비스 이용약관');
    renderLanding();
  }

  // ---------- Landing ----------
  function renderLanding() {
    setHeader({ title: null, back: false, menu: true });
    state.draft = null;
    state.activeObituaryId = null;
    viewEl.innerHTML = `
      <section class="landing">
        <div class="landing__ribbon">⚘</div>
        <div class="landing__sub">간편 부고장</div>
        <div class="landing__title">부고장을 제작합니다</div>
        <div class="landing__desc">유족과 조문객들에게 전할 안내를 작성해보세요</div>
        <div class="landing__visual"><span>⚘</span></div>
        <div class="landing__cta">
          <button class="btn btn--secondary" id="btnMy">나의 부고장 관리</button>
          <button class="btn btn--primary" id="btnCreate">부고장 만들기</button>
        </div>
      </section>
    `;
    $('#btnMy').addEventListener('click', () => openMyObituariesSheet());
    $('#btnCreate').addEventListener('click', () => { state.draft = newObituary(); navigate('create'); });
  }

  // ---------- My obituaries ----------
  function renderMyObituaries() {
    setHeader({ title: '나의 부고장 관리', back: true, menu: false });
    const list = storage.list();
    viewEl.innerHTML = `
      <div class="list">
        ${list.length === 0
        ? `<div class="list__empty">아직 작성한 부고장이 없습니다.</div>`
        : list.map(renderListCard).join('')
      }
      </div>
      <div class="bottom-cta">
        <button class="btn btn--primary btn--block" id="btnNew">부고장 만들기</button>
      </div>
    `;
    $('#btnNew').addEventListener('click', () => { state.draft = newObituary(); navigate('create'); });

    viewEl.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-act]');
      if (!btn) return;
      const id = btn.closest('.list__card').dataset.id;
      const act = btn.dataset.act;
      if (act === 'view') navigate('detail', { id });
      else if (act === 'share') openShareSheet(id);
      else if (act === 'continue') {
        const obit = storage.get(id);
        if (obit) { state.draft = JSON.parse(JSON.stringify(obit)); navigate('edit', { id }); }
      } else if (act === 'delete') {
        askPassword(id, () => {
          openModal({
            title: '부고장을 삭제하시겠습니까?',
            desc: '삭제된 부고장은 복구할 수 없습니다.',
            actions: [
              { label: '취소' },
              { label: '삭제하기', primary: true, value: 'del' },
            ]
          }).then((v) => { if (v === 'del') { storage.remove(id); toast('부고장이 삭제되었습니다.'); renderMyObituaries(); } });
        });
      }
    });
  }
  function renderListCard(o) {
    const d = o.deceased;
    const isDraft = o.status === 'draft';
    const isEnded = o.status === 'ended';
    const statusLabel = isDraft ? '임시저장' : (isEnded ? '장례 종료' : '장례 중');
    const statusClass = isDraft ? 'list__status--draft' : (isEnded ? 'list__status--ended' : '');
    const meta = isDraft
      ? `<div class="list__meta"><span class="label">임시저장</span>${fmtDate(o.updatedAt.slice(0, 10))}</div>`
      : `<div class="list__meta">
            <span class="label">별세일</span>${fmtDate(o.funeral.deathAt?.slice(0, 10) || d.death)}
         </div>`;
    const actions = isDraft
      ? `<button class="list__btn" data-act="delete">삭제하기</button>
         <button class="list__btn" data-act="continue">이어서 작성하기</button>`
      : `<button class="list__btn" data-act="view">상세보기</button>
         <button class="list__btn" data-act="share">공유하기</button>`;
    return `
      <article class="list__card" data-id="${o.id}">
        <div class="list__row">
          <div class="list__name">${escapeHtml(d.name || '(미입력)')}님</div>
          <span class="list__status ${statusClass}">${statusLabel}</span>
        </div>
        ${meta}
        <div class="list__actions">${actions}</div>
      </article>
    `;
  }

  // ---------- Editor (create / edit) ----------
  function renderEditor() {
    if (state.route === 'edit' && (!state.draft || state.draft.id !== state.params.id)) {
      const o = storage.get(state.params.id);
      if (!o) { navigate('landing'); return; }
      state.draft = JSON.parse(JSON.stringify(o));
    }
    if (!state.draft) state.draft = newObituary();
    if (!state.draft.mourners || state.draft.mourners.length === 0) {
      state.draft.mourners = [{ relation: '', name: '' }];
    }
    if (!state.draft.donations || state.draft.donations.length === 0) {
      state.draft.donations = [{ owner: '', bank: '', account: '' }];
    }
    if (!state.draft.deceased.titles || state.draft.deceased.titles.length === 0) {
      // migrate legacy fields if present
      const legacy = [state.draft.deceased.title, state.draft.deceased.roles]
        .filter(Boolean).join('\n').split('\n').filter(Boolean);
      state.draft.deceased.titles = legacy.length ? legacy : [''];
      delete state.draft.deceased.title;
      delete state.draft.deceased.roles;
    }

    const isEdit = state.route === 'edit';
    setHeader({ title: isEdit ? '부고장 수정하기' : '부고장 만들기', back: true, menu: false });

    const d = state.draft;
    if (isEdit && isHashed(d.password)) {
      state.editOriginalPasswordHash = d.password;
      d.password = '';
    } else if (!isEdit) {
      state.editOriginalPasswordHash = null;
    }
    viewEl.innerHTML = `
      <div class="create-page">
        <div class="builder-notice"><span class="req">*</span> 표시는 필수 입력 항목입니다. 꼭 입력해주세요.</div>

        <!-- 고인 정보 -->
        <section class="section">
          <div class="section__head">
            <div class="section__title"><span class="icon-bullet">⚘</span>고인 정보</div>
          </div>
          <div class="field">
            <label class="field__label">성함<span class="req">*</span></label>
            <input class="input" data-bind="deceased.name" value="${escapeHtml(d.deceased.name)}" placeholder="홍길동" />
          </div>
          <div class="field">
            <label class="field__label">생년월일</label>
            <div style="display:grid;grid-template-columns:3fr 1fr;gap:8px;">
              <input class="input" id="birthInput" data-bind="deceased.birth" value="${escapeHtml(d.deceased.birth || '')}" placeholder="예)810910" inputmode="numeric" maxlength="6" />
              <input class="input" id="ageInput" value="${ageDisplay(d.deceased.birth)}" placeholder="향년" disabled />
            </div>
            <div class="field__hint">* 입력 시 향년 나이를 자동 계산합니다</div>
          </div>
          <div class="field">
            <label class="field__label">직함</label>
            <div id="titlesList">
              ${(d.deceased.titles || ['']).map((t, i, arr) => titleRow(t, i, arr.length)).join('')}
            </div>
            <button class="btn btn--secondary btn--block" id="addTitle" style="height:44px;margin-top:8px;">+ 추가하기</button>
          </div>
          <div class="field">
            <label class="field__label">영정 사진 (선택)</label>
            ${d.deceased.photo ? `
              <div class="photo-filled ${d.deceased.photoBW ? 'is-bw' : ''}">
                <div class="photo-filled__thumb">${photoCropImgHTML(d.deceased, 96, 120)}</div>
                <div class="photo-filled__meta">
                  <div class="title">영정 사진 등록 완료</div>
                  <div>${d.deceased.photoBW ? '흑백 모드' : '컬러'} · 확대 ${Number(d.deceased.photoScale || 1).toFixed(2)}x</div>
                  <div class="photo-filled__actions">
                    <button type="button" class="btn btn--secondary" id="editPhoto">편집하기</button>
                    <button type="button" class="btn btn--secondary" id="removePhoto">삭제</button>
                  </div>
                </div>
              </div>
            ` : `
              <div class="photo-upload">
                <button type="button" class="photo-upload__btn" id="addPhoto">+ 영정 사진 추가</button>
                <div class="photo-upload__hint">이미지 파일(jpg, png) · 최대 20MB</div>
              </div>
            `}
          </div>
        </section>

        <!-- 상주 정보 -->
        <section class="section">
          <div class="section__head">
            <div class="section__title"><span class="icon-bullet">⚘</span>상주 정보</div>
            <button class="btn--text" id="addMourner" style="font-size:13px;">+ 추가하기</button>
          </div>
          <div id="mournersList">
            ${d.mourners.map((m, i) => mournerRow(m, i)).join('') || '<div class="muted text-center" style="font-size:12px;padding:8px 0;">상주를 추가해주세요</div>'}
          </div>
        </section>

        <!-- 장례 일정 -->
        <section class="section">
          <div class="section__head">
            <div class="section__title"><span class="icon-bullet">⚘</span>장례 일정</div>
          </div>
          <div class="field">
            <label class="field__label">별세 일시<span class="req">*</span></label>
            <input class="input" type="datetime-local" data-bind="funeral.deathAt" value="${d.funeral.deathAt}" />
          </div>
          <div class="field-row">
            <div class="field">
              <label class="field__label">입관 일시</label>
              <input class="input" type="datetime-local" data-bind="funeral.encoffinAt" value="${d.funeral.encoffinAt}" />
            </div>
            <div class="field">
              <label class="field__label">발인 일시</label>
              <input class="input" type="datetime-local" data-bind="funeral.carryAt" value="${d.funeral.carryAt}" />
            </div>
          </div>
          <div class="field">
            <label class="field__label">빈소</label>
            <input class="input" data-bind="funeral.funeralHome" value="${escapeHtml(d.funeral.funeralHome)}" placeholder="○○병원 장례식장 1호실" />
          </div>
          <div class="field">
            <label class="field__label">장지</label>
            <input class="input" data-bind="funeral.place" value="${escapeHtml(d.funeral.place)}" placeholder="화장장 / 추모공원" />
          </div>
        </section>

        <!-- 알리는 글 -->
        <section class="section">
          <div class="section__head">
            <div class="section__title"><span class="icon-bullet">⚘</span>알리는 글</div>
            <span class="section__optional">선택</span>
          </div>
          <div class="field">
            <textarea class="textarea" maxlength="500" data-bind="notice" placeholder="황망한 마음에 일일이 직접 연락드리지 못함을 널리 헤아려주시기 바랍니다.">${escapeHtml(d.notice)}</textarea>
            <div class="field__counter"><span id="noticeCount">${(d.notice || '').length}</span>/500</div>
          </div>
        </section>

        <!-- 마음을 전하는 곳 -->
        <section class="section">
          <div class="section__head">
            <div class="section__title"><span class="icon-bullet">⚘</span>마음을 전하는 곳</div>
            ${d.noDonation ? '' : `<button class="btn btn--secondary" id="addDonation" style="height:32px;padding:0 12px;font-size:13px;">+ 추가하기</button>`}
          </div>
          <div id="donationsList">
            ${d.noDonation ? '' : d.donations.map((x, i) => donationRow(x, i)).join('')}
          </div>
          <label class="checkbox" style="margin-top:14px;">
            <input type="checkbox" id="noDonationChk" ${d.noDonation ? 'checked' : ''}>
            <span class="checkbox__box"></span>
            <span>부조금을 받지 않겠습니다</span>
          </label>
        </section>

        <!-- 작성자 정보 -->
        <section class="section">
          <div class="section__head">
            <div class="section__title"><span class="icon-bullet">⚘</span>작성자 정보</div>
          </div>
          <div class="field">
            <label class="field__label">작성자 성함<span class="req">*</span></label>
            <input class="input" data-bind="author.name" value="${escapeHtml(d.author.name)}" placeholder="작성자 성함" />
          </div>
          <div class="field">
            <label class="field__label">연락처<span class="req">*</span></label>
            <input class="input" type="tel" data-bind="author.phone" value="${escapeHtml(d.author.phone)}" placeholder="010-1234-5678" />
          </div>
          <div class="field">
            <label class="field__label">고인과의 관계</label>
            <input class="input" data-bind="author.relation" value="${escapeHtml(d.author.relation)}" placeholder="예: 장남" />
          </div>
        </section>

        <!-- 메시지 받기 -->
        <section class="section">
          <div class="section__head">
            <div class="section__title"><span class="icon-bullet">⚘</span>추모 메시지 받기</div>
            <span class="toggle ${d.messagesEnabled ? 'is-on' : ''}" data-toggle="messagesEnabled"></span>
          </div>
          <div class="muted" style="font-size:12px;">조문객들에게 추모 메시지를 받을 수 있어요.</div>
        </section>

        <!-- 비밀번호 -->
        <section class="section">
          <div class="section__head">
            <div class="section__title"><span class="icon-bullet">🔒</span>부고장 비밀번호<span class="req">*</span></div>
          </div>
          <div class="field">
            <input class="input" type="password" inputmode="numeric" maxlength="6" data-bind="password" value="${d.password}" placeholder="${isEdit && state.editOriginalPasswordHash ? '변경 시 새 6자리 입력 (비우면 기존 유지)' : '6자리 숫자'}" />
            <div class="field__hint">${isEdit && state.editOriginalPasswordHash ? '비밀번호를 바꾸지 않으려면 빈 칸으로 두세요.' : '부고장 수정/삭제 시 필요합니다.'}</div>
          </div>
        </section>

        <section class="section">
          <label class="checkbox" id="termsCheck">
            <input type="checkbox" id="termsAgree">
            <span class="checkbox__box"></span>
            <span>개인정보 수집 및 이용에 동의합니다.</span>
          </label>
        </section>
      </div>

      <div class="bottom-cta bottom-cta--two">
        <button class="btn btn--secondary" id="btnSaveDraft">임시저장</button>
        <button class="btn btn--primary" id="btnPreview">미리보기</button>
      </div>
    `;

    bindEditor();
  }

  function titleRow(value, i, total) {
    // show trash when: (i > 0) OR (only row AND has value)
    const hasValue = !!(value && value.trim());
    const showTrash = (total > 1 && i > 0) || (total === 1 && hasValue);
    const cols = showTrash ? '1fr auto' : '1fr';
    return `
      <div class="field-row" data-row="title" data-i="${i}" style="grid-template-columns:${cols};gap:6px;margin-bottom:8px;">
        <input class="input" data-bind-arr="deceased.titles.${i}" data-title-input="${i}" value="${escapeHtml(value || '')}" placeholder="직함을 입력해 주세요" />
        ${showTrash ? `<button class="btn--icon" data-remove="title" data-i="${i}" aria-label="삭제">🗑</button>` : ''}
      </div>
    `;
  }

  function mournerRow(m, i) {
    const isFirst = i === 0;
    const namePlaceholder = isFirst ? '성함*' : '성함';
    const relLabel = m.relation || (isFirst ? '관계*' : '관계 선택');
    return `
      <div class="field-row" data-row="mourner" data-i="${i}" style="margin-bottom:8px;">
        <button type="button" class="select-trigger ${m.relation ? '' : 'is-placeholder'}" data-pick="mourner-rel" data-i="${i}">
          <span>${escapeHtml(relLabel)}</span><span class="chev">▾</span>
        </button>
        <div style="display:flex;gap:6px;">
          <input class="input" style="flex:1;" data-bind-arr="mourners.${i}.name" value="${escapeHtml(m.name || '')}" placeholder="${namePlaceholder}" ${isFirst ? 'required' : ''} />
          ${isFirst ? '' : `<button class="btn--icon" data-remove="mourner" data-i="${i}" aria-label="삭제">🗑</button>`}
        </div>
      </div>
    `;
  }

  function donationRow(x, i) {
    const isFirst = i === 0;
    const groupLabel = isFirst ? '대표 계좌' : '추가 계좌';
    return `
      <div class="donation-row" data-row="donation" data-i="${i}">
        <div class="donation-row__head">
          <span class="donation-row__label">${groupLabel}</span>
          ${isFirst ? '' : `<button class="btn--icon donation-row__del" data-remove="donation" data-i="${i}" aria-label="계좌 삭제">🗑</button>`}
        </div>
        <div class="field-row">
          <button type="button" class="select-trigger ${x.relation ? '' : 'is-placeholder'}" data-pick="donation-rel" data-i="${i}">
            <span>${escapeHtml(x.relation || '관계*')}</span><span class="chev">▾</span>
          </button>
          <input class="input" data-bind-arr="donations.${i}.owner" value="${escapeHtml(x.owner || '')}" placeholder="예금주*" required />
        </div>
        <div class="field-row" style="margin-top:6px;">
          <button type="button" class="select-trigger ${x.bank ? '' : 'is-placeholder'}" data-pick="bank" data-i="${i}">
            <span>${escapeHtml(x.bank || '은행*')}</span><span class="chev">▾</span>
          </button>
          <input class="input" data-bind-arr="donations.${i}.account" value="${escapeHtml(x.account || '')}" placeholder="계좌번호*" inputmode="numeric" required />
        </div>
      </div>
    `;
  }

  function bindEditor() {
    const d = state.draft;

    // bind inputs
    viewEl.querySelectorAll('[data-bind]').forEach((el) => {
      el.addEventListener('input', () => {
        if (el.dataset.bind === 'deceased.birth') {
          el.value = (el.value || '').replace(/\D/g, '').slice(0, 6);
          const ageEl = $('#ageInput');
          if (ageEl) ageEl.value = ageDisplay(el.value);
        }
        setByPath(d, el.dataset.bind, el.value);
        if (el.dataset.bind === 'notice') $('#noticeCount').textContent = el.value.length;
        updateCTAState();
      });
    });
    viewEl.querySelectorAll('[data-bind-arr]').forEach((el) => {
      el.addEventListener('input', () => {
        setByPath(d, el.dataset.bindArr, el.value);
        if (el.dataset.titleInput !== undefined) refreshTitles();
      });
    });
    // Bottom-sheet pickers
    viewEl.querySelectorAll('[data-pick]').forEach((el) => {
      el.addEventListener('click', () => {
        const kind = el.dataset.pick;
        if (kind === 'sex') {
          openSelectSheet({
            title: '성별 선택', layout: 'grid', options: SEX_OPTIONS, value: d.deceased.sex,
            onSelect: (v) => { d.deceased.sex = v; renderEditor(); }
          });
        } else if (kind === 'mourner-rel') {
          const i = +el.dataset.i;
          openSelectSheet({
            title: '관계 선택', layout: 'grid', options: RELATION_OPTIONS, value: d.mourners[i]?.relation,
            onSelect: (v) => { d.mourners[i].relation = v; renderEditor(); }
          });
        } else if (kind === 'bank') {
          const i = +el.dataset.i;
          openSelectSheet({
            title: '은행 선택', layout: 'list', options: BANK_OPTIONS, value: d.donations[i]?.bank,
            onSelect: (v) => { d.donations[i].bank = v; renderEditor(); }
          });
        } else if (kind === 'donation-rel') {
          const i = +el.dataset.i;
          openSelectSheet({
            title: '관계 선택', layout: 'grid', options: RELATION_OPTIONS, value: d.donations[i]?.relation,
            onSelect: (v) => { d.donations[i].relation = v; renderEditor(); }
          });
        }
      });
    });

    viewEl.querySelectorAll('[data-toggle]').forEach((el) => {
      el.addEventListener('click', () => {
        const path = el.dataset.toggle;
        const v = !getByPath(d, path);
        setByPath(d, path, v);
        el.classList.toggle('is-on', v);
        if (path === 'deceased.photoBW') {
          const p = viewEl.querySelector('.photo-preview');
          if (p) p.classList.toggle('is-bw', v);
        }
      });
    });

    // photo: open full popup editor
    const openEditor = () => openPhotoEditor(
      {
        photo: d.deceased.photo,
        bw: d.deceased.photoBW,
        scale: d.deceased.photoScale,
        offsetXRel: d.deceased.photoOffsetXRel,
        offsetYRel: d.deceased.photoOffsetYRel,
      },
      (result) => {
        d.deceased.photo = result.photo || '';
        d.deceased.photoBW = !!result.bw;
        d.deceased.photoScale = result.scale || 1;
        d.deceased.photoOffsetXRel = result.offsetXRel || 0;
        d.deceased.photoOffsetYRel = result.offsetYRel || 0;
        d.deceased.photoNW = result.nw || 0;
        d.deceased.photoNH = result.nh || 0;
        renderEditor();
      }
    );
    $('#addPhoto')?.addEventListener('click', openEditor);
    $('#editPhoto')?.addEventListener('click', openEditor);
    $('#removePhoto')?.addEventListener('click', () => {
      d.deceased.photo = '';
      d.deceased.photoBW = false;
      d.deceased.photoScale = 1;
      renderEditor();
    });
    // legacy file input path (safe no-op if element not present)
    const photoInput = $('#photoInput');
    photoInput?.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (!file) return;
      if (file.size > 20 * 1024 * 1024) return toast('파일 크기는 20MB 이하만 가능합니다.');
      const reader = new FileReader();
      reader.onload = (ev) => {
        d.deceased.photo = ev.target.result;
        renderEditor();
      };
      reader.readAsDataURL(file);
    });

    // titles (직함)
    const refreshTitles = () => {
      const list = d.deceased.titles || [''];
      const host = $('#titlesList');
      if (!host) return;
      // preserve focus
      const active = document.activeElement;
      const focusIdx = active?.dataset?.titleInput;
      const caret = active?.selectionStart;
      host.innerHTML = list.map((t, i, arr) => titleRow(t, i, arr.length)).join('');
      // rebind only the new rows
      host.querySelectorAll('[data-bind-arr]').forEach((el) => {
        el.addEventListener('input', () => {
          setByPath(d, el.dataset.bindArr, el.value);
          refreshTitles();
        });
      });
      host.querySelectorAll('[data-remove="title"]').forEach((b) => {
        b.addEventListener('click', () => {
          const i = +b.dataset.i;
          if (list.length === 1) list[0] = '';
          else list.splice(i, 1);
          refreshTitles();
        });
      });
      // restore focus
      if (focusIdx !== undefined) {
        const next = host.querySelector(`[data-title-input="${focusIdx}"]`);
        if (next) { next.focus(); try { next.setSelectionRange(caret, caret); } catch { } }
      }
    };
    $('#addTitle')?.addEventListener('click', () => {
      if (!d.deceased.titles) d.deceased.titles = [''];
      d.deceased.titles.push('');
      refreshTitles();
      setTimeout(() => {
        const rows = $('#titlesList').querySelectorAll('[data-title-input]');
        rows[rows.length - 1]?.focus();
      }, 0);
    });
    refreshTitles();

    // mourners
    $('#addMourner').addEventListener('click', () => {
      d.mourners.push({ relation: '', name: '' });
      renderEditor();
    });
    viewEl.querySelectorAll('[data-remove="mourner"]').forEach((b) => {
      b.addEventListener('click', () => {
        d.mourners.splice(+b.dataset.i, 1);
        renderEditor();
      });
    });

    // donations
    $('#addDonation')?.addEventListener('click', () => {
      d.donations.push({ relation: '', owner: '', bank: '', account: '' });
      renderEditor();
    });
    $('#noDonationChk')?.addEventListener('change', (e) => {
      d.noDonation = e.target.checked;
      renderEditor();
    });
    viewEl.querySelectorAll('[data-remove="donation"]').forEach((b) => {
      b.addEventListener('click', () => {
        d.donations.splice(+b.dataset.i, 1);
        renderEditor();
      });
    });

    // CTA
    $('#btnSaveDraft').addEventListener('click', () => {
      if (!d.password && state.editOriginalPasswordHash) d.password = state.editOriginalPasswordHash;
      d.status = 'draft';
      d.updatedAt = new Date().toISOString();
      storage.upsert(d);
      toast('저장되었습니다.');
      navigate('my');
    });
    $('#btnPreview').addEventListener('click', () => {
      if (!d.password && state.editOriginalPasswordHash) d.password = state.editOriginalPasswordHash;
      navigate('preview');
    });
  }

  function updateCTAState() { /* preview button always enabled */ }

  function validate(d) {
    if (!d.deceased.name?.trim()) return '필수항목을 다시 확인해주세요.';
    if (!d.funeral.deathAt) return '필수항목을 다시 확인해주세요.';
    if (!d.author.name?.trim()) return '필수항목을 다시 확인해주세요.';
    if (!d.author.phone?.trim()) return '필수항목을 다시 확인해주세요.';
    if (!isHashed(d.password) && !/^\d{6}$/.test(d.password || '')) return '비밀번호는 6자리 숫자입니다.';
    return null;
  }

  function getByPath(o, p) { return p.split('.').reduce((a, k) => a?.[k], o); }
  function setByPath(o, p, v) {
    const keys = p.split('.');
    let cur = o;
    for (let i = 0; i < keys.length - 1; i++) {
      const k = keys[i]; const nk = keys[i + 1];
      if (!(k in cur)) cur[k] = /^\d+$/.test(nk) ? [] : {};
      cur = cur[k];
    }
    cur[keys[keys.length - 1]] = v;
  }

  // ---------- Preview ----------
  function renderPreview() {
    setHeader({ title: '부고장 미리보기', back: true, menu: false });
    const d = state.draft;
    viewEl.innerHTML = obituaryHTML(d, { preview: true });
    viewEl.insertAdjacentHTML('beforeend', `
      <div class="bottom-cta bottom-cta--two">
        <button class="btn btn--secondary" id="btnEdit">편집하기</button>
        <button class="btn btn--primary" id="btnPublish">등록하기</button>
      </div>
    `);
    $('#btnEdit').addEventListener('click', () => navigate('create'));
    $('#btnPublish').addEventListener('click', () => {
      d.status = 'published';
      d.updatedAt = new Date().toISOString();
      storage.upsert(d);
      toast('부고장 링크가 복사되었습니다.');
      try { navigator.clipboard?.writeText(`${location.href.split('#')[0]}#detail/${d.id}`); } catch { }
      navigate('detail', { id: d.id });
    });
  }

  // ---------- Detail (recipient view) ----------
  function renderDetail() {
    const id = state.params.id;
    const o = storage.get(id);
    if (!o) { toast('부고장을 찾을 수 없습니다.'); return navigate('landing'); }
    state.activeObituaryId = id;
    setHeader({ title: '부고장', back: true, menu: true, activeId: id });

    if (o.status === 'ended') return navigate('ended');

    viewEl.innerHTML = obituaryHTML(o, { preview: false });
    viewEl.insertAdjacentHTML('beforeend', `
      <div class="bottom-cta bottom-cta--two">
        <button class="btn btn--secondary" id="btnFlower">헌화하기</button>
        <button class="btn btn--primary" id="btnShare">공유하기</button>
      </div>
    `);
    $('#btnFlower').addEventListener('click', () => toast('마음이 전달되었습니다.'));
    $('#btnShare').addEventListener('click', () => openShareSheet(id));
  }

  function obituaryHTML(o, { preview }) {
    const d = o.deceased;
    const f = o.funeral;
    const headTitle = d.name ? `삼가 ${escapeHtml(d.name)}님의<br>명복을 빕니다.` : '삼가 고인의<br>명복을 빕니다.';

    const photoBlock = d.showPhoto && d.photo
      ? `<div class="deceased__photo ${d.photoBW ? 'is-bw' : ''}">${photoCropImgHTML(d, 80, 100)}</div>`
      : `<div class="deceased__photo" style="display:flex;align-items:center;justify-content:center;color:#bbb;">⚘</div>`;

    return `
      <div class="obituary">
        <header class="obituary__hero">
          <div class="ribbon">⚘</div>
          <div class="head-title">${headTitle}</div>
          <div class="head-sub">${fmtDate(f.deathAt?.slice(0, 10) || d.death)} 별세</div>
        </header>
        <div class="obituary__body">

          <section class="card">
            <div class="card__title"><span class="ico">⚘</span>고인 정보</div>
            <div class="deceased">
              ${photoBlock}
              <div>
                <div class="deceased__name">故 ${escapeHtml(d.name || '')}님</div>
                <div class="deceased__meta">
                  ${[fmtDate(f.deathAt?.slice(0, 10) || d.death) + ' 별세', ageDisplay(d.birth)]
        .filter(Boolean).join(' · ')}
                </div>
                ${d.showTitle && (d.titles || []).some(t => t && t.trim()) ? `<div class="deceased__roles">${(d.titles || []).filter(t => t && t.trim()).map(escapeHtml).join('<br>')}</div>` : ''}
              </div>
            </div>
          </section>

          ${o.mourners.length ? `
            <section class="card">
              <div class="card__title"><span class="ico">⚘</span>상주</div>
              <dl class="def-list">
                ${o.mourners.map(m => `<div class="row"><dt>${escapeHtml(m.relation || '')}</dt><dd>${escapeHtml(m.name || '')}</dd></div>`).join('')}
              </dl>
            </section>
          `: ''}

          <section class="card">
            <div class="card__title"><span class="ico">⚘</span>장례 일정</div>
            <dl class="def-list">
              <div class="row"><dt>별세일</dt><dd>${fmtDateTime(f.deathAt)}</dd></div>
              ${f.encoffinAt ? `<div class="row"><dt>입관일시</dt><dd>${fmtDateTime(f.encoffinAt)}</dd></div>` : ''}
              ${f.carryAt ? `<div class="row"><dt>발인일시</dt><dd>${fmtDateTime(f.carryAt)}</dd></div>` : ''}
              ${f.place ? `<div class="row"><dt>장지</dt><dd>${escapeHtml(f.place)}</dd></div>` : ''}
            </dl>
          </section>

          ${f.funeralHome ? `
            <section class="card">
              <div class="card__title"><span class="ico">⚘</span>빈소</div>
              <div class="def-list">${escapeHtml(f.funeralHome)}</div>
              <div class="copy-row" style="margin-top:6px;">
                <button data-copy="${escapeHtml(f.funeralHome)}">주소 복사</button>
              </div>
            </section>
          `: ''}

          ${o.notice ? `
            <section class="card">
              <div class="card__title"><span class="ico">⚘</span>알리는 글</div>
              <div class="message-block">${escapeHtml(o.notice)}</div>
            </section>
          `: ''}

          ${!o.noDonation && o.donations.some(x => x.bank || x.account) ? `
            <section class="card">
              <div class="card__title"><span class="ico">⚘</span>마음을 전하는 곳</div>
              ${o.donations.filter(x => x.bank || x.account).map(x => `
                <div style="margin-bottom:10px;">
                  <div style="font-size:13px;color:var(--c-text-2);">
                    ${escapeHtml(x.relation || '')}${x.relation && x.owner ? ' · ' : ''}${escapeHtml(x.owner || '')}
                  </div>
                  <div class="copy-row">
                    <span class="label">${escapeHtml(x.bank || '')}</span>
                    <span>${escapeHtml(x.account || '')}</span>
                    <button data-copy="${escapeHtml(x.account || '')}" data-toast="계좌 번호가 복사되었습니다.">복사</button>
                  </div>
                </div>
              `).join('')}
            </section>
          `: ''}

          ${o.messagesEnabled ? `
            <section class="card">
              <div class="card__title" style="display:flex;justify-content:space-between;">
                <span><span class="ico">⚘</span>추모 메시지</span>
                ${!preview ? `<button class="btn--text" id="goMessages" style="font-size:12px;">더보기 ›</button>` : ''}
              </div>
              ${o.messages.slice(0, 2).length === 0
          ? `<div class="muted" style="font-size:13px;">아직 추모 메시지가 없습니다.</div>`
          : o.messages.slice(0, 2).map(messageItem).join('')}
            </section>
          `: ''}

        </div>
      </div>
    `;
  }

  function messageItem(m) {
    return `
      <div class="message-list-item" data-msg-id="${m.id}">
        <div class="row">
          <div><span class="name">${escapeHtml(m.name)}</span> <span style="margin-left:6px;">${fmtDate(m.createdAt.slice(0, 10))}</span></div>
          <button class="btn--text" data-msg-del="${m.id}" style="font-size:12px;">삭제</button>
        </div>
        <div class="body">${escapeHtml(m.body)}</div>
      </div>
    `;
  }

  // ---------- Detail-level event delegation ----------
  document.addEventListener('click', (e) => {
    const copy = e.target.closest('[data-copy]');
    if (copy) {
      const v = copy.dataset.copy;
      navigator.clipboard?.writeText(v).then(() => toast(copy.dataset.toast || '복사되었습니다.'));
    }
    const goMsg = e.target.closest('#goMessages');
    if (goMsg) navigate('messages', { id: state.activeObituaryId });

    const delMsg = e.target.closest('[data-msg-del]');
    if (delMsg) {
      const mid = delMsg.dataset.msgDel;
      const o = storage.get(state.activeObituaryId);
      if (!o) return;
      openModal({
        title: '추모 메시지를 삭제하시겠습니까?',
        body: `<div class="field"><input type="password" inputmode="numeric" maxlength="6" class="input" id="msgPw" placeholder="작성 시 입력한 비밀번호" /></div>`,
        actions: [
          { label: '취소' },
          {
            label: '삭제하기', primary: true, onClick: async (panel) => {
              const v = panel.querySelector('#msgPw').value;
              const m = o.messages.find(x => x.id === mid);
              if (!m || !(await matchPw(m.password, v))) { toast('비밀번호가 일치하지 않습니다.'); return false; }
              o.messages = o.messages.filter(x => x.id !== mid);
              storage.upsert(o);
              toast('추모 메시지가 삭제되었습니다.');
              if (state.route === 'messages') renderMessages();
              else if (state.route === 'detail') renderDetail();
            }
          },
        ]
      });
    }
  });

  // ---------- Share sheet ----------
  function openShareSheet(id) {
    const url = `${location.href.split('#')[0]}#detail/${id}`;
    openSheet(`
      <div class="sheet-head"><div class="sheet-title">공유하기</div><button class="sheet-close" id="ssClose">×</button></div>
      <div class="share-list">
        <button data-share="kakao"><span class="icon">💬</span><span>카카오톡으로 공유</span></button>
        <button data-share="copy"><span class="icon">🔗</span><span>링크 복사하기</span></button>
        <button data-share="native"><span class="icon">📤</span><span>다른 앱으로 공유</span></button>
      </div>
    `);
    $('#ssClose').addEventListener('click', closeSheet);
    sheetPanel.querySelectorAll('[data-share]').forEach((b) => b.addEventListener('click', () => {
      const t = b.dataset.share;
      if (t === 'copy') { navigator.clipboard?.writeText(url); toast('부고장 링크가 복사되었습니다.'); }
      else if (t === 'native' && navigator.share) { navigator.share({ url, title: '부고장' }).catch(() => { }); }
      else if (t === 'kakao') { toast('카카오톡 SDK 연동이 필요합니다.'); }
      closeSheet();
    }));
  }

  // ---------- Messages list ----------
  function renderMessages() {
    const id = state.params.id || state.activeObituaryId;
    const o = storage.get(id);
    if (!o) return navigate('landing');
    state.activeObituaryId = id;
    setHeader({ title: '추모 메시지', back: true, menu: false });
    viewEl.innerHTML = `
      <div class="list" style="background:var(--c-surface);min-height:100%;">
        ${o.messages.length === 0
        ? `<div class="list__empty">아직 추모 메시지가 없습니다.<br><br>아래 + 버튼을 눌러 첫 메시지를 남겨주세요.</div>`
        : o.messages.map(messageItem).join('')}
      </div>
      <button class="fab" id="addMsg" aria-label="추모 메시지 작성">+</button>
    `;
    $('#addMsg').addEventListener('click', () => navigate('message-write', { id }));
  }

  // ---------- Message write ----------
  function renderMessageWrite() {
    const id = state.params.id || state.activeObituaryId;
    setHeader({ title: '추모 메시지 작성', back: true, menu: false });
    viewEl.innerHTML = `
      <div style="padding:16px;background:var(--c-surface);min-height:100%;">
        <div class="field">
          <label class="field__label">이름</label>
          <input class="input" id="mName" placeholder="작성자명을 입력해주세요." />
        </div>
        <div class="field">
          <label class="field__label">비밀번호</label>
          <input class="input" id="mPw" type="password" inputmode="numeric" maxlength="6" placeholder="수정, 삭제를 위해 필요합니다." />
          <div class="field__hint">6자리 숫자로 입력해주세요</div>
        </div>
        <div class="field">
          <label class="field__label">내용</label>
          <textarea class="textarea" id="mBody" maxlength="100" placeholder="삼가 고인의 명복을 빕니다."></textarea>
          <div class="field__counter"><span id="mCount">0</span>/100</div>
        </div>
      </div>
      <div class="bottom-cta">
        <button class="btn btn--primary btn--block" id="mSubmit" disabled>등록하기</button>
      </div>
    `;
    const name = $('#mName'), pw = $('#mPw'), body = $('#mBody'), submit = $('#mSubmit'), count = $('#mCount');
    const update = () => {
      count.textContent = body.value.length;
      submit.disabled = !(name.value.trim() && /^\d{6}$/.test(pw.value) && body.value.trim());
    };
    [name, pw, body].forEach(el => el.addEventListener('input', update));
    submit.addEventListener('click', () => {
      const o = storage.get(id);
      if (!o) return;
      o.messages.unshift({
        id: 'm_' + Math.random().toString(36).slice(2, 8),
        name: name.value.trim(),
        password: pw.value,
        body: body.value.trim(),
        createdAt: new Date().toISOString(),
      });
      storage.upsert(o);
      toast('추모 메시지가 등록되었습니다.');
      navigate('messages', { id });
    });
  }

  // ---------- Ended page ----------
  function renderEnded() {
    setHeader({ title: '부고장', back: true, menu: false });
    viewEl.innerHTML = `
      <div class="ended">
        <div class="ribbon">⚘</div>
        <div class="label">장례 종료</div>
        <h2>따뜻한 위로 감사합니다.</h2>
        <p>바쁘신 와중에도 조문해 주시고 위로해주셔서 감사합니다.<br>
        덕분에 무사히 장례를 마쳤습니다.<br>
        베풀어 주신 마음 오래도록 간직하겠습니다.</p>
      </div>
    `;
  }

  // ---------- Policy pages ----------
  function renderPolicy(title) {
    setHeader({ title, back: true, menu: false });
    viewEl.innerHTML = `
      <div class="policy">
        <p>본 ${escapeHtml(title)} 문서는 데모용입니다. 실제 서비스 운영 시 약관 내용으로 교체해주세요. 약관 내용 입니다. 약관 내용 입니다. 약관 내용 입니다. 약관 내용 입니다. 약관 내용 입니다. 약관 내용 입니다. 약관 내용 입니다.</p>
      </div>
    `;
  }

  // ---------- URL hash routing (for shared links) ----------
  function syncFromHash() {
    const hash = location.hash.slice(1);
    if (!hash) return false;
    const [route, ...rest] = hash.split('/');
    if (route === 'detail' && rest[0]) {
      navigate('detail', { id: rest[0] });
      return true;
    }
    return false;
  }
  window.addEventListener('hashchange', syncFromHash);

  // ---------- Boot ----------
  if (!syncFromHash()) renderLanding();
})();
