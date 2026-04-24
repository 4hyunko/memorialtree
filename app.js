/* ======================================================
   수정Memorial Tree - Web App (free obituary builder)
   Single-file vanilla JS SPA. Persistence: Firestore.
   ====================================================== */

import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.14.1/firebase-app.js';
import {
  getFirestore, collection, onSnapshot,
  doc, setDoc, deleteDoc
} from 'https://www.gstatic.com/firebasejs/10.14.1/firebase-firestore.js';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

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

// Supabase (영정사진 저장)
const SUPABASE_URL = 'https://nfmiybikusxwsiudaxzw.supabase.co';
const SUPABASE_KEY = 'sb_publishable_6zqulXul93cHF74IG3H2EQ_pI2n_e4e';
const SUPABASE_BUCKET = 'photo';
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

(() => {
  'use strict';

  // ---------- Storage (Firestore for data, Supabase Storage for photos) ----------
  const SESSION_KEY = 'mt.session.v1';
  const PHOTO_KEY = (id) => 'mt.photo.' + id;
  // localStorage fallback — 구데이터 호환용 (신규 저장은 Supabase로)
  const getLocalPhoto = (id) => { try { return localStorage.getItem(PHOTO_KEY(id)) || ''; } catch { return ''; } };
  const removeLocalPhoto = (id) => { try { localStorage.removeItem(PHOTO_KEY(id)); } catch { } };

  // Supabase Storage helpers
  async function uploadPhotoToSupabase(obitId, dataUrl) {
    if (!dataUrl || !dataUrl.startsWith('data:')) return dataUrl || '';
    const res = await fetch(dataUrl);
    const blob = await res.blob();
    const mime = blob.type || 'image/jpeg';
    const ext = (mime.split('/')[1] || 'jpg').split(';')[0];
    const path = `${obitId}.${ext}`;
    const { error } = await supabase.storage
      .from(SUPABASE_BUCKET)
      .upload(path, blob, { upsert: true, contentType: mime });
    if (error) throw error;
    const { data: urlData } = supabase.storage.from(SUPABASE_BUCKET).getPublicUrl(path);
    return `${urlData.publicUrl}?v=${Date.now()}`;
  }
  async function removePhotoFromSupabase(obitId) {
    const paths = ['jpg', 'jpeg', 'png', 'webp', 'gif'].map(e => `${obitId}.${e}`);
    try { await supabase.storage.from(SUPABASE_BUCKET).remove(paths); } catch (e) { /* noop */ }
  }

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
      const originalPhoto = obit.deceased?.photo || '';
      // 캐시는 즉시 원본(dataURL 포함)으로 반영해 UI가 끊기지 않게 함
      const cached = JSON.parse(JSON.stringify(obit));
      const idx = this._cache.findIndex(o => o.id === obit.id);
      if (idx >= 0) this._cache[idx] = cached; else this._cache.unshift(cached);

      (async () => {
        try {
          // 1) 사진 처리
          let photoUrl = originalPhoto;
          if (originalPhoto.startsWith('data:')) {
            // 새 dataURL → Supabase 업로드
            try {
              photoUrl = await uploadPhotoToSupabase(obit.id, originalPhoto);
              removeLocalPhoto(obit.id); // 마이그레이션: 옛 localStorage 지움
            } catch (e) {
              console.error('photo upload failed', e);
              toast('사진 업로드에 실패했습니다.');
              photoUrl = '';
            }
          } else if (!originalPhoto) {
            // 사진 제거 → Supabase에서도 삭제
            await removePhotoFromSupabase(obit.id);
            removeLocalPhoto(obit.id);
          }
          // 캐시 URL 갱신
          if (cached.deceased) cached.deceased.photo = photoUrl;

          // 2) Firestore 저장
          const plain = JSON.parse(JSON.stringify(obit));
          if (plain.deceased) plain.deceased.photo = photoUrl;
          if (plain.password && !isHashed(plain.password)) plain.password = await hashPw(plain.password);
          if (Array.isArray(plain.messages)) {
            for (const m of plain.messages) {
              if (m.password && !isHashed(m.password)) m.password = await hashPw(m.password);
            }
          }
          await setDoc(doc(obitsCol, obit.id), plain);
        } catch (e) {
          console.error('Firestore upsert failed', e);
          toast('다시 시도해주세요.');
        }
      })();
      return obit;
    },
    remove(id) {
      this._cache = this._cache.filter(o => o.id !== id);
      removeLocalPhoto(id);
      removePhotoFromSupabase(id).catch(() => { });
      deleteDoc(doc(obitsCol, id)).catch((e) => {
        console.error('Firestore delete failed', e);
        toast('다시 시도해주세요.');
      });
    }
  };

  onSnapshot(obitsCol, (snap) => {
    storage._cache = snap.docs.map(d => {
      const data = d.data();
      if (data.deceased && !data.deceased.photo) {
        // 신규 저장은 Firestore에 URL 저장, 없으면 legacy localStorage 폴백
        data.deceased.photo = getLocalPhoto(d.id);
      }
      return data;
    });
    storage._ready = true;
    if (['landing', 'my', 'detail'].includes(state.route)) render();
  }, (err) => {
    console.error('Firestore subscribe failed', err);
    toast('다시 시도해주세요.');
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
  const formatScheduleValue = (iso, timeUndecided) => {
    if (!iso) return '';
    const [datePart, timePart] = iso.split('T');
    const dateStr = datePart.replaceAll('-', '.');
    if (timeUndecided || !timePart) return dateStr;
    return `${dateStr} ${timePart.slice(0, 5)}`;
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
      passwordConfirm: '',
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
        deathTerm: '별세', // 5-a 임종 용어
        deathAt: todayISO(), // 5-b 임종일 (default: today)
        encoffinAt: '', // 5-c 입관 일시
        encoffinTimeUndecided: false,
        carryAt: '', // 5-d 발인 일시
        carryTimeUndecided: false,
        carryDateUndecided: false,
        place: '', // 5-e 장지
        funeralHome: '', // 장례식장 (표시용 요약 문자열)
        funeralHomeData: null, // 장례식장 구조화 데이터 { name, addr, telno, homepageUrl, ctpv, sigungu }
        funeralHomeMode: 'search', // 'search' | 'manual'
        funeralHomeName: '',
        funeralHomeAddr: '',
        funeralHomePhone: '',
        funeralHomeRoom: '',
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
    authedPhone: '', // normalized phone (digits only) that passed the "나의 부고장 관리" auth
    authedPw: '', // plain password (session memory only) used to filter obits in my list
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
      let hasMatch = false;
      for (const o of candidates) {
        if (await matchPw(o.password, pw)) { hasMatch = true; break; }
      }
      if (!hasMatch) {
        errEl.hidden = false;
        toast('일치하는 부고장이 없습니다.');
        return;
      }
      state.authedPhone = normPhone;
      state.authedPw = pw;
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

  // 장사시설 검색 bottom-sheet (장지)
  const SIDO_LIST = [
    { code: '서울특별시', label: '서울' },
    { code: '부산광역시', label: '부산' },
    { code: '대구광역시', label: '대구' },
    { code: '인천광역시', label: '인천' },
    { code: '광주광역시', label: '광주' },
    { code: '대전광역시', label: '대전' },
    { code: '울산광역시', label: '울산' },
    { code: '세종특별자치시', label: '세종' },
    { code: '경기도', label: '경기' },
    { code: '강원특별자치도', label: '강원' },
    { code: '충청북도', label: '충북' },
    { code: '충청남도', label: '충남' },
    { code: '전북특별자치도', label: '전북' },
    { code: '전라남도', label: '전남' },
    { code: '경상북도', label: '경북' },
    { code: '경상남도', label: '경남' },
    { code: '제주특별자치도', label: '제주' },
  ];

  let funeralAllCache = null;

  async function fetchAllFuneralFacilities() {
    if (funeralAllCache) return funeralAllCache;
    const res = await fetch('./data/funeral-halls.json', { cache: 'force-cache' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    funeralAllCache = Array.isArray(data?.items) ? data.items : [];
    return funeralAllCache;
  }

  // Daum Postcode 기반 주소 검색 (도로명/지번/우편번호)
  function openPostcodeSheet({ value, onConfirm }) {
    if (!window.daum?.Postcode) {
      toast('주소 검색을 불러올 수 없습니다. 잠시 후 다시 시도해주세요.');
      return;
    }
    openSheet(`
      <div class="sheet-head">
        <div class="sheet-title">주소 검색</div>
        <button class="sheet-close" id="psClose" aria-label="닫기">×</button>
      </div>
      <div id="psContainer" style="width:100%;height:60vh;min-height:380px;"></div>
    `);
    $('#psClose').addEventListener('click', closeSheet);
    const container = $('#psContainer');
    new window.daum.Postcode({
      oncomplete: (data) => {
        const addr = data.roadAddress || data.jibunAddress || data.address || '';
        const extra = [];
        if (data.bname) extra.push(data.bname);
        if (data.buildingName) extra.push(data.buildingName);
        const full = extra.length ? `${addr} (${extra.join(', ')})` : addr;
        closeSheet();
        onConfirm(full, data);
      },
      width: '100%',
      height: '100%',
    }).embed(container, { q: value || '', autoClose: false });
  }

  function openAddressSearchSheet({ title = '장례식장 검색', value, onConfirm, mode = 'funeral' }) {
    let allItems = [];
    let loading = true;
    let errorMsg = '';
    let query = '';
    let page = 1;
    const PAGE_SIZE = 10;
    const PAGE_WINDOW = 5;

    const getFiltered = () => {
      const q = query.trim();
      if (!q) return allItems;
      return allItems.filter(it =>
        (it.fcltNm || '').includes(q) ||
        (it.addr || '').includes(q) ||
        (it.sigungu || '').includes(q) ||
        (it.ctpv || '').includes(q)
      );
    };

    const renderPagination = (totalPages) => {
      if (totalPages <= 1) return '';
      let start = Math.max(1, page - Math.floor(PAGE_WINDOW / 2));
      let end = Math.min(totalPages, start + PAGE_WINDOW - 1);
      start = Math.max(1, end - PAGE_WINDOW + 1);
      const pages = [];
      for (let i = start; i <= end; i++) pages.push(i);
      return `
        <div class="pagination">
          <button class="pagination__btn" data-page="${page - 1}" ${page === 1 ? 'disabled' : ''} aria-label="이전">‹</button>
          ${pages.map(p => `<button class="pagination__btn ${p === page ? 'is-on' : ''}" data-page="${p}">${p}</button>`).join('')}
          <button class="pagination__btn" data-page="${page + 1}" ${page === totalPages ? 'disabled' : ''} aria-label="다음">›</button>
        </div>
      `;
    };

    const computeView = () => {
      const list = getFiltered();
      const totalPages = Math.max(1, Math.ceil(list.length / PAGE_SIZE));
      if (page > totalPages) page = totalPages;
      if (page < 1) page = 1;
      const start = (page - 1) * PAGE_SIZE;
      const slice = list.slice(start, start + PAGE_SIZE);
      return { list, totalPages, slice };
    };

    const renderSummary = () => {
      if (loading || errorMsg) return '';
      const { list, totalPages } = computeView();
      if (list.length === 0) return '';
      return `<div class="search-summary">총 ${list.length}건 · ${page}/${totalPages} 페이지</div>`;
    };

    const renderResults = () => {
      if (loading) return `<div class="search-empty">전국 장례식장 정보를 불러오는 중...</div>`;
      if (errorMsg) return `<div class="search-empty">${escapeHtml(errorMsg)}</div>`;
      const { list, slice } = computeView();
      if (list.length === 0) {
        return `
          <div class="search-empty">
            <div>검색 결과가 없습니다.</div>
            <div style="font-size:12px;color:var(--c-text-3);margin-top:4px;">다른 키워드로 시도하거나 직접 입력해주세요.</div>
            <button type="button" class="btn btn--secondary" id="asEmptyManual" style="margin-top:12px;">직접 입력하기</button>
          </div>
        `;
      }
      return slice.map((it) => {
        const name = it.fcltNm || '-';
        const addr = it.addr || '';
        const full = addr ? `${name} (${addr})` : name;
        const primary = mode === 'address' ? addr || name : name;
        const secondary = mode === 'address' ? (name && name !== '-' ? name : '') : addr;
        const tagLabel = mode === 'address' ? '도로명' : '';
        return `
          <div class="search-item" data-addr="${escapeHtml(full)}" data-name="${escapeHtml(name)}" data-addr-only="${escapeHtml(addr)}" data-phone="${escapeHtml(it.telno || '')}" data-telno="${escapeHtml(it.telno || '')}" data-homepage="${escapeHtml(it.homepageUrl || '')}" data-ctpv="${escapeHtml(it.ctpv || '')}" data-sigungu="${escapeHtml(it.sigungu || '')}">
            <div class="search-item__info">
              <div class="addr-name">${tagLabel ? `<span class="zip-chip">${tagLabel}</span>` : ''}${escapeHtml(primary)}</div>
              ${secondary ? `<div class="road">${escapeHtml(secondary)}</div>` : ''}
              ${mode !== 'address' && it.telno ? `<div class="jibun"><span class="tag">전화</span>${escapeHtml(it.telno)}</div>` : ''}
            </div>
            <button type="button" class="search-item__btn" data-select>선택</button>
          </div>

        `;
      }).join('');
    };

    const renderFooterPagination = () => {
      if (loading || errorMsg) return '';
      const { list, totalPages } = computeView();
      if (list.length === 0) return '';
      return renderPagination(totalPages);
    };

    const updateResults = () => {
      const summaryEl = $('#asSummary');
      if (summaryEl) summaryEl.innerHTML = renderSummary();
      const el = $('#asResults');
      if (el) el.innerHTML = renderResults();
      const pagEl = $('#asPagination');
      if (pagEl) pagEl.innerHTML = renderFooterPagination();
      bindItems();
      bindPagination();
    };

    const bindItems = () => {
      document.querySelectorAll('#asResults .search-item').forEach(row => {
        const selectBtn = row.querySelector('[data-select]');
        const trigger = (ev) => {
          ev?.stopPropagation?.();
          closeSheet();
          const name = row.dataset.name || '';
          const addr = row.dataset.addrOnly || '';
          const display = row.dataset.addr || (addr ? `${name} (${addr})` : name);
          onConfirm(display, {
            name,
            addr,
            phone: row.dataset.phone || '',
            fcltNm: name,
            telno: row.dataset.telno || row.dataset.phone || '',
            homepageUrl: row.dataset.homepage || '',
            ctpv: row.dataset.ctpv || '',
            sigungu: row.dataset.sigungu || ''
          });
        };
        selectBtn?.addEventListener('click', trigger);
        row.addEventListener('click', (e) => { if (e.target === selectBtn) return; trigger(e); });
      });
      document.querySelector('#asEmptyManual')?.addEventListener('click', () => {
        closeSheet();
        onConfirm('', { name: '', addr: '', phone: '', switchToManual: true });
      });
    };

    const bindPagination = () => {
      document.querySelectorAll('#asPagination [data-page]').forEach(btn => {
        btn.addEventListener('click', () => {
          if (btn.disabled) return;
          const p = Number(btn.dataset.page);
          if (!Number.isFinite(p) || p < 1) return;
          page = p;
          updateResults();
          const resultsEl = $('#asResults');
          if (resultsEl) resultsEl.scrollTop = 0;
        });
      });
    };

    const placeholder = mode === 'address' ? '도로명 또는 지번으로 검색' : '장례식장명 또는 주소로 검색';
    openSheet(`
      <div class="sheet-head">
        <div class="sheet-title">${escapeHtml(title)}</div>
        <button class="sheet-close" id="asClose" aria-label="닫기">×</button>
      </div>
      <div class="search-input search-input--icon">
        <svg class="search-input__icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <input class="input" id="asInput" placeholder="${escapeHtml(placeholder)}" value="${escapeHtml(value || '')}" autocomplete="off" />
      </div>
      <div id="asSummary">${renderSummary()}</div>
      <div class="search-results" id="asResults">${renderResults()}</div>
      <div id="asPagination">${renderFooterPagination()}</div>
    `);

    const inputEl = $('#asInput');
    let timer = null;
    inputEl.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        query = inputEl.value;
        page = 1;
        updateResults();
      }, 120);
    });

    $('#asClose').addEventListener('click', closeSheet);

    bindItems();
    bindPagination();

    setTimeout(() => inputEl.focus(), 50);

    (async () => {
      try {
        allItems = await fetchAllFuneralFacilities();
      } catch (e) {
        errorMsg = '데이터를 불러오지 못했습니다. 잠시 후 다시 시도해주세요.';
        console.error('[funeral api]', e);
      } finally {
        loading = false;
        updateResults();
      }
    })();
  }

  // 관계 선택 bottom-sheet (Bottomsheet-1 item 2)
  const RELATION_GROUPS = [
    { key: '자녀 및 배우자', subs: ['배우자', '아들', '딸', '며느리', '사위'] },
    { key: '손자녀', subs: ['손자', '손녀', '외손자', '외손녀', '손부 (손자의 아내)', '손서 (손녀의 남편)', '외손부 (외손자의 아내)', '외손서 (외손녀의 남편)'] },
    { key: '형제자매', subs: ['형', '오빠', '누나', '언니', '남동생', '여동생'] },
    { key: '부모 및 친척', subs: ['부', '모', '고모', '이모', '백부', '백모', '숙부', '숙모', '조부', '조모'] },
    { key: '형제의 배우자', subs: ['형수', '제수', '매형', '매제'] },
  ];
  const RELATION_SUB_TO_GROUP = (() => {
    const m = new Map();
    RELATION_GROUPS.forEach(g => g.subs.forEach(s => m.set(s, g.key)));
    return m;
  })();
  function openRelationSheet({ value, onConfirm }) {
    const isCustom = value && !RELATION_SUB_TO_GROUP.has(value);
    let mainKey = RELATION_SUB_TO_GROUP.get(value) || RELATION_GROUPS[0].key;
    let selectedSub = RELATION_SUB_TO_GROUP.has(value) ? value : '';
    let customText = isCustom ? value : '';

    const render = () => {
      const group = RELATION_GROUPS.find(g => g.key === mainKey) || RELATION_GROUPS[0];
      const canConfirm = !!selectedSub || !!customText.trim();
      sheetPanel.innerHTML = `
        <div class="sheet-head">
          <div class="sheet-title">관계 선택</div>
          <button class="sheet-close" id="relClose" aria-label="닫기">×</button>
        </div>
        <div class="picker-section-label">대메뉴</div>
        <div class="sheet-grid sheet-grid--3">
          ${RELATION_GROUPS.map(g => `<button type="button" class="sheet-grid__item ${g.key === mainKey ? 'is-selected' : ''}" data-main="${escapeHtml(g.key)}">${escapeHtml(g.key)}</button>`).join('')}
        </div>
        <div class="picker-section-label" style="margin-top:14px;">소메뉴</div>
        <div class="sheet-grid sheet-grid--3">
          ${group.subs.map(s => `<button type="button" class="sheet-grid__item ${s === selectedSub ? 'is-selected' : ''}" data-sub="${escapeHtml(s)}">${escapeHtml(s)}</button>`).join('')}
        </div>
        <div class="picker-section-label" style="margin-top:14px;">직접 입력</div>
        <input type="text" class="input" id="relCustom" placeholder="입력해주세요." value="${escapeHtml(customText)}" maxlength="8" />
        <div class="sheet-confirm">
          <button class="btn btn--primary btn--block" id="relConfirm" ${canConfirm ? '' : 'disabled'}>선택 완료</button>
        </div>
      `;
      sheetPanel.querySelectorAll('[data-main]').forEach(btn => btn.addEventListener('click', () => {
        mainKey = btn.dataset.main;
        selectedSub = '';
        render();
      }));
      sheetPanel.querySelectorAll('[data-sub]').forEach(btn => btn.addEventListener('click', () => {
        selectedSub = btn.dataset.sub;
        customText = '';
        render();
      }));
      sheetPanel.querySelector('#relCustom').addEventListener('input', (e) => {
        customText = e.target.value;
        if (customText.trim()) selectedSub = '';
        sheetPanel.querySelectorAll('[data-sub].is-selected').forEach(el => el.classList.remove('is-selected'));
        sheetPanel.querySelector('#relConfirm').disabled = !customText.trim();
      });
      sheetPanel.querySelector('#relClose').addEventListener('click', closeSheet);
      sheetPanel.querySelector('#relConfirm').addEventListener('click', () => {
        const out = customText.trim() || selectedSub;
        if (!out) return;
        closeSheet();
        onConfirm(out);
      });
    };
    sheetEl.setAttribute('aria-hidden', 'false');
    render();
  }

  // 임종 용어 bottom-sheet (Bottomsheet-3 item 5)
  const DEATH_TERM_GENERAL = ['별세', '영면', '작고', '운명', '서거', '타계', '순직', '전사'];
  const DEATH_TERM_RELIGION = [
    { value: '소천', label: '소천 (기독교)' },
    { value: '선종', label: '선종 (천주교)' },
    { value: '왕생', label: '왕생 (불교)' },
    { value: '입적', label: '입적 (스님)' },
  ];
  function openDeathTermSheet({ value, onConfirm }) {
    const generalSet = new Set(DEATH_TERM_GENERAL);
    const religionSet = new Set(DEATH_TERM_RELIGION.map(r => r.value));
    let area = generalSet.has(value) ? 'general' : religionSet.has(value) ? 'religion' : (value ? 'custom' : 'general');
    let selected = value || '별세';
    let customText = area === 'custom' ? value : '';

    const render = () => {
      sheetPanel.innerHTML = `
        <div class="sheet-head">
          <div class="sheet-title">임종 용어</div>
          <button class="sheet-close" id="dtmClose" aria-label="닫기">×</button>
        </div>
        <div class="picker-section-label">일반</div>
        <div class="sheet-grid sheet-grid--4">
          ${DEATH_TERM_GENERAL.map(t => `<button type="button" class="sheet-grid__item ${area === 'general' && selected === t ? 'is-selected' : ''}" data-area="general" data-v="${t}">${t}</button>`).join('')}
        </div>
        <div class="picker-section-label" style="margin-top:14px;">종교</div>
        <div class="sheet-grid">
          ${DEATH_TERM_RELIGION.map(r => `<button type="button" class="sheet-grid__item ${area === 'religion' && selected === r.value ? 'is-selected' : ''}" data-area="religion" data-v="${r.value}">${escapeHtml(r.label)}</button>`).join('')}
        </div>
        <div class="picker-section-label" style="margin-top:14px;">직접 입력</div>
        <input type="text" class="input" id="dtmCustom" placeholder="입력해주세요." value="${escapeHtml(customText)}" maxlength="20" />
        <div class="sheet-confirm">
          <button class="btn btn--primary btn--block" id="dtmConfirm" ${(area === 'custom' ? !!customText.trim() : !!selected) ? '' : 'disabled'}>선택 완료</button>
        </div>
      `;
      sheetPanel.querySelectorAll('[data-area]').forEach(btn => btn.addEventListener('click', () => {
        area = btn.dataset.area;
        selected = btn.dataset.v;
        customText = '';
        render();
      }));
      const customEl = sheetPanel.querySelector('#dtmCustom');
      customEl.addEventListener('input', (e) => {
        customText = e.target.value;
        if (customText.trim()) {
          area = 'custom';
          selected = '';
        }
        sheetPanel.querySelectorAll('.sheet-grid__item.is-selected').forEach(el => el.classList.remove('is-selected'));
        sheetPanel.querySelector('#dtmConfirm').disabled = !customText.trim();
      });
      sheetPanel.querySelector('#dtmClose').addEventListener('click', closeSheet);
      sheetPanel.querySelector('#dtmConfirm').addEventListener('click', () => {
        const out = area === 'custom' ? customText.trim() : selected;
        if (!out) return;
        closeSheet();
        onConfirm(out);
      });
    };
    sheetEl.setAttribute('aria-hidden', 'false');
    render();
  }

  // Calendar / DateTime bottom-sheet (spec items 8/9/10)
  function buildCalendarHTML(year, month, selected, todayStr, allowFuture) {
    const startWeekday = new Date(year, month, 1).getDay();
    const daysInMonth = new Date(year, month + 1, 0).getDate();
    const prevDays = new Date(year, month, 0).getDate();
    const cells = [];
    for (let i = startWeekday - 1; i >= 0; i--) {
      cells.push(`<button type="button" class="calendar__day calendar__day--muted" disabled>${prevDays - i}</button>`);
    }
    for (let day = 1; day <= daysInMonth; day++) {
      const ds = `${year}-${String(month + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
      const isToday = ds === todayStr;
      const isSelected = ds === selected;
      const isFuture = !allowFuture && ds > todayStr;
      cells.push(`<button type="button" class="calendar__day ${isSelected ? 'is-selected' : ''} ${isToday ? 'is-today' : ''}" data-date="${ds}" ${isFuture ? 'disabled' : ''}>${day}</button>`);
    }
    const trailing = (7 - (cells.length % 7)) % 7;
    for (let i = 1; i <= trailing; i++) {
      cells.push(`<button type="button" class="calendar__day calendar__day--muted" disabled>${i}</button>`);
    }
    return `<div class="calendar__grid">${cells.join('')}</div>`;
  }

  function openDatePickerSheet({ title, value, defaultDate, allowFuture = true, onConfirm }) {
    const todayStr = todayISO();
    const fallback = defaultDate || todayStr;
    let selected = value || fallback;
    const initial = new Date(selected + 'T00:00');
    let year = initial.getFullYear();
    let month = initial.getMonth();

    const render = () => {
      const canNext = allowFuture || (year < new Date().getFullYear() || (year === new Date().getFullYear() && month < new Date().getMonth()));
      sheetPanel.innerHTML = `
        <div class="sheet-head">
          <div class="sheet-title">${escapeHtml(title)}</div>
          <button class="sheet-close" id="dpClose" aria-label="닫기">×</button>
        </div>
        <div class="picker-section-label">날짜 선택<span class="req">*</span></div>
        <div class="calendar__head">
          <button type="button" class="calendar__nav" id="dpPrev">‹</button>
          <div class="calendar__title">${year}.${String(month + 1).padStart(2, '0')}</div>
          <button type="button" class="calendar__nav" id="dpNext" ${canNext ? '' : 'disabled'}>›</button>
        </div>
        <div class="calendar__weekdays">${['S', 'M', 'T', 'W', 'T', 'F', 'S'].map(w => `<div>${w}</div>`).join('')}</div>
        ${buildCalendarHTML(year, month, selected, todayStr, allowFuture)}
        <div class="sheet-actions">
          <button type="button" class="btn btn--secondary" id="dpReset">초기화</button>
          <button type="button" class="btn btn--primary" id="dpConfirm">선택 완료</button>
        </div>
      `;
      sheetPanel.querySelectorAll('[data-date]').forEach(b => b.addEventListener('click', () => {
        selected = b.dataset.date;
        render();
      }));
      sheetPanel.querySelector('#dpPrev').addEventListener('click', () => {
        month--;
        if (month < 0) { month = 11; year--; }
        render();
      });
      sheetPanel.querySelector('#dpNext').addEventListener('click', () => {
        if (sheetPanel.querySelector('#dpNext').disabled) return;
        month++;
        if (month > 11) { month = 0; year++; }
        render();
      });
      sheetPanel.querySelector('#dpReset').addEventListener('click', () => {
        selected = '';
        const now = new Date();
        year = now.getFullYear();
        month = now.getMonth();
        render();
      });
      sheetPanel.querySelector('#dpClose').addEventListener('click', closeSheet);
      sheetPanel.querySelector('#dpConfirm').addEventListener('click', () => {
        closeSheet();
        onConfirm(selected);
      });
    };
    sheetEl.setAttribute('aria-hidden', 'false');
    render();
  }

  function openDateTimePickerSheet({ title, value, timeUndecided, dateUndecided, allowDateUndecided, onConfirm }) {
    const todayStr = todayISO();
    const initialDate = value ? value.split('T')[0] : todayStr;
    const initialTime = (value && value.split('T')[1]) ? value.split('T')[1].slice(0, 5) : '09:00';
    let selected = initialDate;
    let hh = initialTime.split(':')[0] || '09';
    let mm = (initialTime.split(':')[1] === '30') ? '30' : '00';
    let tUndecided = !!timeUndecided;
    let dUndecided = !!dateUndecided;
    const init = new Date(selected + 'T00:00');
    let year = init.getFullYear();
    let month = init.getMonth();

    const HOURS = Array.from({ length: 24 }, (_, i) => String(i).padStart(2, '0'));
    const MINS = ['00', '30'];

    const render = () => {
      const disabledArea = dUndecided;
      sheetPanel.innerHTML = `
        <div class="sheet-head">
          <div class="sheet-title">${escapeHtml(title)}</div>
          <button class="sheet-close" id="dtClose" aria-label="닫기">×</button>
        </div>
        <div class="picker-section-label">날짜 선택<span class="req">*</span></div>
        <div class="calendar__head">
          <button type="button" class="calendar__nav" id="dtPrev" ${disabledArea ? 'disabled' : ''}>‹</button>
          <div class="calendar__title">${year}.${String(month + 1).padStart(2, '0')}</div>
          <button type="button" class="calendar__nav" id="dtNext" ${disabledArea ? 'disabled' : ''}>›</button>
        </div>
        <div class="calendar__weekdays">${['S', 'M', 'T', 'W', 'T', 'F', 'S'].map(w => `<div>${w}</div>`).join('')}</div>
        <div ${disabledArea ? 'style="opacity:.4;pointer-events:none;"' : ''}>
          ${buildCalendarHTML(year, month, selected, todayStr, true)}
        </div>
        ${allowDateUndecided ? `
          <label class="checkbox" style="margin-top:12px;">
            <input type="checkbox" id="dtDateUndecided" ${dUndecided ? 'checked' : ''}>
            <span class="checkbox__box"></span>
            <span>아직 발인일이 미정입니다</span>
          </label>
        ` : ''}
        <div class="time-picker">
          <div class="time-picker__col">
            <label>시</label>
            <select class="input" id="dtHour" ${(tUndecided || disabledArea) ? 'disabled' : ''}>
              ${HOURS.map(h => `<option value="${h}" ${h === hh ? 'selected' : ''}>${h}</option>`).join('')}
            </select>
          </div>
          <div class="time-picker__col">
            <label>분</label>
            <select class="input" id="dtMin" ${(tUndecided || disabledArea) ? 'disabled' : ''}>
              ${MINS.map(m => `<option value="${m}" ${m === mm ? 'selected' : ''}>${m}</option>`).join('')}
            </select>
          </div>
        </div>
        <label class="checkbox" style="margin-top:12px;">
          <input type="checkbox" id="dtTimeUndecided" ${tUndecided ? 'checked' : ''} ${disabledArea ? 'disabled' : ''}>
          <span class="checkbox__box"></span>
          <span>시간은 미정입니다</span>
        </label>
        <div class="sheet-actions">
          <button type="button" class="btn btn--secondary" id="dtReset">초기화</button>
          <button type="button" class="btn btn--primary" id="dtConfirm">선택 완료</button>
        </div>
      `;
      sheetPanel.querySelectorAll('[data-date]').forEach(b => b.addEventListener('click', () => {
        selected = b.dataset.date;
        render();
      }));
      sheetPanel.querySelector('#dtPrev').addEventListener('click', () => {
        if (disabledArea) return;
        month--;
        if (month < 0) { month = 11; year--; }
        render();
      });
      sheetPanel.querySelector('#dtNext').addEventListener('click', () => {
        if (disabledArea) return;
        month++;
        if (month > 11) { month = 0; year++; }
        render();
      });
      sheetPanel.querySelector('#dtHour').addEventListener('change', (e) => { hh = e.target.value; });
      sheetPanel.querySelector('#dtMin').addEventListener('change', (e) => { mm = e.target.value; });
      sheetPanel.querySelector('#dtTimeUndecided').addEventListener('change', (e) => {
        tUndecided = e.target.checked;
        render();
      });
      const dateChk = sheetPanel.querySelector('#dtDateUndecided');
      if (dateChk) dateChk.addEventListener('change', (e) => {
        dUndecided = e.target.checked;
        if (dUndecided) tUndecided = false;
        render();
      });
      sheetPanel.querySelector('#dtReset').addEventListener('click', () => {
        selected = '';
        hh = '09'; mm = '00';
        tUndecided = false;
        dUndecided = false;
        const now = new Date();
        year = now.getFullYear();
        month = now.getMonth();
        render();
      });
      sheetPanel.querySelector('#dtClose').addEventListener('click', closeSheet);
      sheetPanel.querySelector('#dtConfirm').addEventListener('click', () => {
        closeSheet();
        if (dUndecided) {
          onConfirm({ iso: '', timeUndecided: false, dateUndecided: true });
        } else if (!selected) {
          onConfirm({ iso: '', timeUndecided: false, dateUndecided: false });
        } else {
          const iso = tUndecided ? `${selected}T00:00` : `${selected}T${hh}:${mm}`;
          onConfirm({ iso, timeUndecided: tUndecided, dateUndecided: false });
        }
      });
    };
    sheetEl.setAttribute('aria-hidden', 'false');
    render();
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
    const hash = hashFromRoute(route, params);
    const target = hash || location.pathname + location.search;
    if ((location.hash || '') !== hash) {
      try { history.pushState(null, '', target); } catch { }
    }
    render();
    window.scrollTo({ top: 0, behavior: 'instant' });
  }

  // ---------- Hash routing helpers ----------
  const HASH_ROUTES_WITH_ID = new Set(['detail', 'edit', 'messages', 'message-write']);
  const HASH_ROUTES_NO_ID = new Set(['landing', 'my', 'create', 'preview', 'ended', 'privacy', 'terms']);

  function hashFromRoute(route, params) {
    if (!route || route === 'landing') return '';
    if (HASH_ROUTES_WITH_ID.has(route) && params?.id) return `#${route}/${params.id}`;
    if (HASH_ROUTES_NO_ID.has(route)) return `#${route}`;
    return '';
  }

  function routeFromHash(hash) {
    const h = (hash || '').replace(/^#\/?/, '');
    if (!h) return { route: 'landing', params: {} };
    const [route, id] = h.split('/');
    if (HASH_ROUTES_WITH_ID.has(route) && id) return { route, params: { id } };
    if (HASH_ROUTES_NO_ID.has(route)) return { route, params: {} };
    return { route: 'landing', params: {} };
  }

  function setHeader({ title, back = false, menu = true, saveDraft = false, activeId = null }) {
    $('#headerTitle').innerHTML = title || `<span class="logo-mark">⚘</span> Memorial Tree`;
    $('#headerTitle').dataset.activeId = activeId || '';
    $('#headerBack').hidden = !back;
    $('#headerMenu').style.display = menu ? '' : 'none';
    $('#headerSaveDraft').hidden = !saveDraft;
  }
  $('#headerSaveDraft').addEventListener('click', () => {
    const d = state.draft;
    if (!d) return;
    const hasAuthor = !!(d.author?.phone?.trim() || d.password?.trim() || d.passwordConfirm?.trim());
    if (!hasAuthor) {
      openModal({
        title: '안내',
        desc: '작성자 정보를 입력해 주세요',
        actions: [{ label: '확인', primary: true, value: 'ok' }]
      }).then(() => {
        const phoneEl = $('#authorPhoneInput');
        if (phoneEl) {
          phoneEl.scrollIntoView({ block: 'center' });
          phoneEl.focus();
        }
      });
      return;
    }
    d.status = 'draft';
    d.updatedAt = new Date().toISOString();
    storage.upsert(d);
    toast('저장되었습니다.');
    navigate('my');
  });

  $('#headerBack').addEventListener('click', () => {
    // simple back logic
    if (state.route === 'create' || state.route === 'edit') {
      if (state.draft && hasUnsavedChanges()) {
        openModal({
          title: '안내',
          desc: '지금까지 작성된 내용은 저장되지 않아요.\n마음이 정리되면 그 때 다시 작성해도 괜찮아요.',
          actions: [
            { label: '다음에 작성', value: 'leave' },
            { label: '계속 작성', primary: true },
          ]
        }).then((v) => { if (v === 'leave') { state.draft = null; navigate('landing'); } });
      } else { navigate('landing'); }
    } else if (state.route === 'preview') {
      navigate('create');
    } else if (state.route === 'detail') {
      navigate('landing');
    } else if (state.route === 'edit') {
      navigate('detail', { id: state.params.id });
    } else if (state.route === 'messages' || state.route === 'message-write') {
      const id = state.params.id || state.activeObituaryId;
      if (id) navigate('detail', { id });
      else navigate('landing');
    } else if (['my', 'privacy', 'terms', 'ended'].includes(state.route)) {
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
    setHeader({ title: null, back: false, menu: false });
    state.draft = null;
    state.activeObituaryId = null;
    state.authedPhone = '';
    state.authedPw = '';
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
  async function renderMyObituaries() {
    setHeader({ title: '나의 부고장 관리', back: true, menu: false });
    if (!state.authedPhone || !state.authedPw) return navigate('landing');

    viewEl.innerHTML = `<div class="list__empty">불러오는 중...</div>`;

    const candidates = storage.list().filter(o =>
      (o.author?.phone || '').replace(/\D/g, '') === state.authedPhone
    );
    const matched = await Promise.all(
      candidates.map(async o => (await matchPw(o.password, state.authedPw)) ? o : null)
    );
    const list = matched.filter(Boolean);

    // 비동기 중에 사용자가 다른 화면으로 이동했으면 렌더 건너뜀
    if (state.route !== 'my') return;

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
    const deathDate = fmtDate(o.funeral.deathAt?.slice(0, 10) || d.death);
    const isActive = !isDraft && !isEnded;
    const nameSuffix = isActive && deathDate ? `<span class="list__name-date">${deathDate} ${escapeHtml(o.funeral.deathTerm || '별세')}</span>` : '';
    const meta = isDraft
      ? `<div class="list__meta"><span class="label">임시저장</span>${fmtDate(o.updatedAt.slice(0, 10))}</div>`
      : isActive
        ? `<div class="list__meta"><span class="label">생성일</span>${fmtDate((o.createdAt || o.updatedAt).slice(0, 10))}</div>`
        : `<div class="list__meta">
              <span class="label">${escapeHtml(o.funeral.deathTerm || '별세')}일</span>${deathDate}
           </div>`;
    const actions = isDraft
      ? `<button class="list__btn" data-act="delete">삭제하기</button>
         <button class="list__btn" data-act="continue">이어서 작성하기</button>`
      : `<button class="list__btn" data-act="view">상세보기</button>
         <button class="list__btn" data-act="share">공유하기</button>`;
    return `
      <article class="list__card" data-id="${o.id}">
        <div class="list__row">
          <div class="list__name">${escapeHtml(d.name || '(미입력)')}님${nameSuffix}</div>
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
    setHeader({ title: isEdit ? '부고장 수정하기' : '부고장 만들기', back: true, menu: false, saveDraft: true });

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

        <!-- 장례식장 -->
        <section class="section">
          <div class="section__head">
            <div class="section__title"><span class="icon-bullet">⚘</span>장례식장</div>
          </div>
          <div class="section__notice">장례식장 검색 시 주소와 연락처가 자동 입력됩니다. 목록에 없으면 직접 입력해 주세요.</div>
          ${d.funeral.funeralHomeMode === 'manual' ? `
            <div class="field">
              <label class="field__label">주소</label>
              <button type="button" class="picker-input picker-input--search ${d.funeral.funeralHomeAddr ? '' : 'picker-input--placeholder'}" data-pick-funeral="addressSearch">
                <svg class="picker-input__icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                <span>${d.funeral.funeralHomeAddr ? escapeHtml(d.funeral.funeralHomeAddr) : '주소를 검색해주세요'}</span>
              </button>
            </div>
            <div class="field">
              <label class="field__label">장례식장 이름</label>
              <input class="input" id="fhNameInput" data-bind="funeral.funeralHomeName" value="${escapeHtml(d.funeral.funeralHomeName)}" placeholder="장례식장 이름을 입력해주세요" ${d.funeral.funeralHomeAddr ? '' : 'disabled'} />
            </div>
            <div class="field">
              <label class="field__label">전화번호</label>
              <input class="input" type="tel" inputmode="numeric" id="fhPhoneInput" data-bind="funeral.funeralHomePhone" value="${escapeHtml(d.funeral.funeralHomePhone)}" placeholder="02-1234-5678" ${d.funeral.funeralHomeAddr ? '' : 'disabled'} />
            </div>
            <div class="field">
              <label class="field__label">호실</label>
              <input class="input" data-bind="funeral.funeralHomeRoom" value="${escapeHtml(d.funeral.funeralHomeRoom)}" placeholder="호실을 입력해주세요" />
            </div>
          ` : `
            <div class="field">
              <label class="field__label">장례식장</label>
              <button type="button" class="picker-input picker-input--search ${d.funeral.funeralHomeName ? '' : 'picker-input--placeholder'}" data-pick-funeral="funeralHome">
                <svg class="picker-input__icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                <span>${d.funeral.funeralHomeName ? escapeHtml(d.funeral.funeralHomeName) : '장례식장을 검색해주세요'}</span>
              </button>
            </div>
            ${d.funeral.funeralHomeName ? `
              <div class="fh-info">
                ${d.funeral.funeralHomeAddr ? `<div class="fh-info__row"><span class="fh-info__label">주소</span>${escapeHtml(d.funeral.funeralHomeAddr)}</div>` : ''}
                ${d.funeral.funeralHomePhone ? `<div class="fh-info__row"><span class="fh-info__label">전화</span>${escapeHtml(d.funeral.funeralHomePhone)}</div>` : ''}
              </div>
            ` : ''}
            <div class="field">
              <label class="field__label">호실</label>
              <input class="input" data-bind="funeral.funeralHomeRoom" value="${escapeHtml(d.funeral.funeralHomeRoom)}" placeholder="호실을 입력해주세요" ${d.funeral.funeralHomeName ? '' : 'disabled'} />
            </div>
          `}
          <label class="checkbox" style="margin-top:14px;">
            <input type="checkbox" id="fhManualChk" ${d.funeral.funeralHomeMode === 'manual' ? 'checked' : ''}>
            <span class="checkbox__box"></span>
            <span>직접 입력하기</span>
          </label>
        </section>

        <!-- 장례 일정 -->
        <section class="section">
          <div class="section__head">
            <div class="section__title"><span class="icon-bullet">⚘</span>장례 일정</div>
          </div>
          <div class="field">
            <label class="field__label">임종 용어<span class="req">*</span></label>
            <button type="button" class="picker-input ${d.funeral.deathTerm ? '' : 'picker-input--placeholder'}" data-pick-funeral="term">
              <span>${d.funeral.deathTerm || '임종 용어를 선택해주세요'}</span>
              <span class="picker-input__chevron">⌄</span>
            </button>
          </div>
          <div class="field">
            <label class="field__label">임종일<span class="req">*</span></label>
            <button type="button" class="picker-input ${d.funeral.deathAt ? '' : 'picker-input--placeholder'}" data-pick-funeral="death">
              <span>${d.funeral.deathAt ? fmtDate(d.funeral.deathAt) : '임종일을 선택해주세요'}</span>
              <span class="picker-input__chevron">⌄</span>
            </button>
          </div>
          <div class="field">
            <label class="field__label">입관 일시</label>
            <button type="button" class="picker-input ${d.funeral.encoffinAt ? '' : 'picker-input--placeholder'}" data-pick-funeral="encoffin">
              <span>${formatScheduleValue(d.funeral.encoffinAt, d.funeral.encoffinTimeUndecided) || '입관 일시를 선택해주세요'}</span>
              <span class="picker-input__chevron">⌄</span>
            </button>
          </div>
          <div class="field">
            <label class="field__label">발인 일시</label>
            <button type="button" class="picker-input ${(d.funeral.carryAt || d.funeral.carryDateUndecided) ? '' : 'picker-input--placeholder'}" data-pick-funeral="carry">
              <span>${d.funeral.carryDateUndecided ? '미정' : (formatScheduleValue(d.funeral.carryAt, d.funeral.carryTimeUndecided) || '발인 일시를 선택해주세요')}</span>
              <span class="picker-input__chevron">⌄</span>
            </button>
          </div>
          <div class="field">
            <label class="field__label">장지</label>
            <input class="input" data-bind="funeral.place" value="${escapeHtml(d.funeral.place)}" placeholder="장지를 입력해주세요" />
            <div class="field__help">* 미입력 시 '미정'으로 반영됩니다.</div>
          </div>
        </section>

        <!-- 알리는 글 -->
        <section class="section">
          <div class="section__head">
            <div class="section__title"><span class="icon-bullet">⚘</span>알리는 글</div>
          </div>
          <div class="field">
            <textarea class="textarea" maxlength="200" data-bind="notice" placeholder="황망한 마음에 일일이 직접 연락드리지 못함을 널리 헤아려주시기 바랍니다.">${escapeHtml(d.notice)}</textarea>
            <div class="field__footer">
              <span class="field__help">* 미작성 시 위의 내용으로 반영됩니다.</span>
              <span class="field__counter"><span id="noticeCount">${(d.notice || '').length}</span>/200</span>
            </div>
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

        <!-- 메시지 받기 -->
        <section class="section">
          <div class="section__head">
            <div class="section__title"><span class="icon-bullet">⚘</span>추모 메시지 받기</div>
            <span class="toggle ${d.messagesEnabled ? 'is-on' : ''}" data-toggle="messagesEnabled"></span>
          </div>
          <div class="muted" style="font-size:12px;">조문객들에게 추모 메시지를 받을 수 있어요.</div>
        </section>

        ${!isEdit ? `
        <!-- 작성자 정보 -->
        <section class="section">
          <div class="section__head">
            <div class="section__title"><span class="icon-bullet">⚘</span>작성자 정보</div>
          </div>
          <div class="section__notice">추후 부고장 수정/삭제 시 필요합니다</div>
          <div class="field">
            <label class="field__label">연락처<span class="req">*</span></label>
            <input class="input" type="tel" inputmode="numeric" pattern="[0-9]*" maxlength="13" id="authorPhoneInput" data-bind="author.phone" value="${escapeHtml(d.author.phone)}" placeholder="010-1234-5678" />
          </div>
          <div class="field">
            <label class="field__label">비밀번호<span class="req">*</span></label>
            <input class="input" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="6" id="authorPwInput" data-bind="password" value="${escapeHtml(d.password || '')}" placeholder="6자리 숫자" autocomplete="new-password" />
          </div>
          <div class="field">
            <label class="field__label">비밀번호 확인<span class="req">*</span></label>
            <input class="input" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="6" id="authorPwConfirmInput" data-bind="passwordConfirm" value="${escapeHtml(d.passwordConfirm || '')}" placeholder="6자리 숫자" autocomplete="new-password" />
            <div class="field__hint" id="authorPwConfirmHint"></div>
          </div>
        </section>
        ` : ''}

        <section class="section">
          <label class="checkbox" id="termsCheck">
            <input type="checkbox" id="termsAgree">
            <span class="checkbox__box"></span>
            <span>개인정보 수집 및 이용에 동의합니다.<span class="req">*</span></span>
          </label>
        </section>
      </div>

      <div class="bottom-cta bottom-cta--two">
        <button class="btn btn--secondary" id="btnPreview">미리보기</button>
        <button class="btn btn--primary" id="btnComplete">완료하기</button>
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
          <input class="input" type="tel" data-bind-arr="donations.${i}.account" data-digits-only data-max-digits="14" maxlength="14" value="${escapeHtml(x.account || '')}" placeholder="계좌번호*" inputmode="numeric" pattern="[0-9]*" required />
        </div>
      </div>
    `;
  }

  function bindEditor() {
    const d = state.draft;

    // bind inputs
    viewEl.querySelectorAll('[data-bind]').forEach((el) => {
      if (el.dataset.bind === 'deceased.birth') {
        el.addEventListener('blur', () => {
          const ageEl = $('#ageInput');
          if (ageEl) ageEl.value = ageDisplay(el.value);
        });
      }
      el.addEventListener('input', () => {
        if (el.dataset.bind === 'deceased.birth') {
          el.value = (el.value || '').replace(/\D/g, '').slice(0, 6);
          const ageEl = $('#ageInput');
          if (ageEl) ageEl.value = ageDisplay(el.value);
        }
        if (el.dataset.bind === 'author.phone') {
          const digits = (el.value || '').replace(/\D/g, '').slice(0, 11);
          el.value = digits.length < 4
            ? digits
            : digits.length < 8
              ? `${digits.slice(0, 3)}-${digits.slice(3)}`
              : `${digits.slice(0, 3)}-${digits.slice(3, 7)}-${digits.slice(7)}`;
        }
        if (el.dataset.bind === 'password' || el.dataset.bind === 'passwordConfirm') {
          el.value = (el.value || '').replace(/\D/g, '').slice(0, 6);
        }
        setByPath(d, el.dataset.bind, el.value);
        if (el.dataset.bind === 'notice') $('#noticeCount').textContent = el.value.length;
        if (el.dataset.bind === 'password' || el.dataset.bind === 'passwordConfirm') {
          const hint = $('#authorPwConfirmHint');
          const confirmEl = $('#authorPwConfirmInput');
          if (hint && confirmEl) {
            hint.classList.remove('field__hint--error', 'field__hint--success');
            confirmEl.classList.remove('is-error');
            if (!d.passwordConfirm) {
              hint.textContent = '';
            } else if (d.password === d.passwordConfirm) {
              hint.textContent = '비밀번호가 일치합니다.';
              hint.classList.add('field__hint--success');
            } else {
              hint.textContent = '비밀번호가 일치하지 않습니다.';
              hint.classList.add('field__hint--error');
              confirmEl.classList.add('is-error');
            }
          }
        }
        updateCTAState();
      });
    });
    viewEl.querySelectorAll('[data-bind-arr]').forEach((el) => {
      el.addEventListener('input', () => {
        if (el.hasAttribute('data-digits-only')) {
          let digits = (el.value || '').replace(/\D/g, '');
          const maxDigits = Number(el.dataset.maxDigits) || 0;
          if (maxDigits > 0) digits = digits.slice(0, maxDigits);
          el.value = digits;
        }
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
          openRelationSheet({
            value: d.mourners[i]?.relation,
            onConfirm: (v) => { d.mourners[i].relation = v; renderEditor(); }
          });
        } else if (kind === 'bank') {
          const i = +el.dataset.i;
          openSelectSheet({
            title: '은행 선택', layout: 'list', options: BANK_OPTIONS, value: d.donations[i]?.bank,
            onSelect: (v) => { d.donations[i].bank = v; renderEditor(); }
          });
        } else if (kind === 'donation-rel') {
          const i = +el.dataset.i;
          openRelationSheet({
            value: d.donations[i]?.relation,
            onConfirm: (v) => { d.donations[i].relation = v; renderEditor(); }
          });
        } else if (kind === 'author-rel') {
          openRelationSheet({
            value: d.author.relation,
            onConfirm: (v) => { d.author.relation = v; renderEditor(); }
          });
        }
      });
    });

    // Funeral schedule pickers (date / datetime / select)
    viewEl.querySelectorAll('[data-pick-funeral]').forEach((el) => {
      el.addEventListener('click', () => {
        const kind = el.dataset.pickFuneral;
        if (kind === 'term') {
          openDeathTermSheet({
            value: d.funeral.deathTerm,
            onConfirm: (v) => { d.funeral.deathTerm = v; renderEditor(); }
          });
        } else if (kind === 'death') {
          openDatePickerSheet({
            title: '임종일', value: d.funeral.deathAt, defaultDate: todayISO(), allowFuture: false,
            onConfirm: (v) => { d.funeral.deathAt = v; renderEditor(); }
          });
        } else if (kind === 'encoffin') {
          openDateTimePickerSheet({
            title: '입관 일시',
            value: d.funeral.encoffinAt,
            timeUndecided: d.funeral.encoffinTimeUndecided,
            onConfirm: ({ iso, timeUndecided }) => {
              d.funeral.encoffinAt = iso;
              d.funeral.encoffinTimeUndecided = timeUndecided;
              renderEditor();
            }
          });
        } else if (kind === 'carry') {
          openDateTimePickerSheet({
            title: '발인 일시',
            value: d.funeral.carryAt,
            timeUndecided: d.funeral.carryTimeUndecided,
            dateUndecided: d.funeral.carryDateUndecided,
            allowDateUndecided: true,
            onConfirm: ({ iso, timeUndecided, dateUndecided }) => {
              d.funeral.carryAt = iso;
              d.funeral.carryTimeUndecided = timeUndecided;
              d.funeral.carryDateUndecided = dateUndecided;
              renderEditor();
            }
          });
        } else if (kind === 'funeralHome') {
          openAddressSearchSheet({
            title: '장례식장 검색',
            mode: 'funeral',
            value: d.funeral.funeralHomeName || d.funeral.funeralHome,
            onConfirm: (label, item) => {
              if (item?.switchToManual) {
                d.funeral.funeralHomeMode = 'manual';
                renderEditor();
                return;
              }
              d.funeral.funeralHomeName = item?.name || label;
              d.funeral.funeralHomeAddr = item?.addr || '';
              d.funeral.funeralHomePhone = item?.phone || item?.telno || '';
              d.funeral.funeralHome = label;
              d.funeral.funeralHomeData = item ? {
                name: item.fcltNm || item.name || '',
                addr: item.addr || '',
                telno: item.telno || item.phone || '',
                homepageUrl: item.homepageUrl || '',
                ctpv: item.ctpv || '',
                sigungu: item.sigungu || '',
              } : null;
              renderEditor();
            }
          });
        } else if (kind === 'addressSearch') {
          openPostcodeSheet({
            value: d.funeral.funeralHomeAddr,
            onConfirm: (addr, data) => {
              d.funeral.funeralHomeAddr = addr;
              d.funeral.funeralHome = d.funeral.funeralHomeName
                ? `${d.funeral.funeralHomeName} (${addr})`
                : addr;
              renderEditor();
            }
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
        let composing = false;
        el.addEventListener('compositionstart', () => { composing = true; });
        el.addEventListener('compositionend', () => {
          composing = false;
          setByPath(d, el.dataset.bindArr, el.value);
          maybeRefreshOnInput(el);
        });
        el.addEventListener('input', () => {
          if (composing) return;
          setByPath(d, el.dataset.bindArr, el.value);
          maybeRefreshOnInput(el);
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
    // Refresh DOM only when trash-button visibility for single-row case toggles
    const maybeRefreshOnInput = (el) => {
      const list = d.deceased.titles || [''];
      if (list.length !== 1) return;
      const row = el.closest('[data-row="title"]');
      const hasTrash = !!row?.querySelector('[data-remove="title"]');
      const shouldHaveTrash = !!(list[0] && list[0].trim());
      if (hasTrash !== shouldHaveTrash) refreshTitles();
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

    // 장례식장 모드 토글 (체크박스)
    $('#fhManualChk')?.addEventListener('change', (e) => {
      d.funeral.funeralHomeMode = e.target.checked ? 'manual' : 'search';
      renderEditor();
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
    $('#btnPreview').addEventListener('click', () => {
      if (!d.password && state.editOriginalPasswordHash) d.password = state.editOriginalPasswordHash;
      navigate('preview');
    });
    $('#btnComplete').addEventListener('click', () => {
      const err = validate(d);
      if (err) { toast(err); return; }
      if (!$('#termsAgree')?.checked) { toast('필수항목을 다시 확인해주세요.'); return; }
      // 해시되기 전 raw 비밀번호를 캡처해서 자동 인증에 사용
      const rawPw = !isHashed(d.password) ? (d.password || '') : '';
      if (!d.password && state.editOriginalPasswordHash) d.password = state.editOriginalPasswordHash;
      d.status = 'active';
      d.updatedAt = new Date().toISOString();
      storage.upsert(d);
      // 나의 부고장 자동 로그인: raw 비밀번호가 있을 때만 갱신 (편집 중 비번 변경 포함)
      if (rawPw) {
        state.authedPhone = (d.author?.phone || '').replace(/\D/g, '');
        state.authedPw = rawPw;
      }
      toast('저장되었습니다.');
      navigate('my');
    });
  }

  function updateCTAState() { /* preview button always enabled */ }

  function validate(d) {
    if (!d.deceased.name?.trim()) return '필수항목을 다시 확인해주세요.';
    if (!d.funeral.deathAt) return '필수항목을 다시 확인해주세요.';
    if (!d.author.phone?.trim()) return '필수항목을 다시 확인해주세요.';
    if (!isHashed(d.password) && !/^\d{6}$/.test(d.password || '')) return '비밀번호는 6자리 숫자입니다.';
    if (!isHashed(d.password) && d.password !== d.passwordConfirm) return '비밀번호가 일치하지 않습니다.';
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

  // ---------- Kakao Maps ----------
  let kakaoMapsPromise = null;
  function loadKakaoMaps() {
    if (kakaoMapsPromise) return kakaoMapsPromise;
    kakaoMapsPromise = new Promise((resolve, reject) => {
      if (!window.kakao?.maps) { reject(new Error('Kakao SDK not present')); return; }
      if (window.kakao.maps.services) { resolve(window.kakao); return; }
      window.kakao.maps.load(() => resolve(window.kakao));
    });
    return kakaoMapsPromise;
  }

  async function initFuneralMaps(root) {
    const containers = (root || document).querySelectorAll('[data-kakao-map]:not([data-kakao-ready])');
    if (!containers.length) return;
    let kakao;
    try {
      kakao = await loadKakaoMaps();
    } catch (e) {
      console.warn('[kakao-maps] SDK load failed', e);
      containers.forEach(el => {
        el.setAttribute('data-kakao-ready', 'error');
        el.innerHTML = '<div class="venue__map-msg">지도를 불러올 수 없습니다.</div>';
      });
      return;
    }
    const geocoder = new kakao.maps.services.Geocoder();
    const places = new kakao.maps.services.Places();

    containers.forEach(el => {
      let addr = el.dataset.addr || '';
      let name = el.dataset.name || '';
      // 레거시 데이터 보정: name과 addr이 "{name} ({addr})" 형태로 함께 들어온 경우 분리
      if (name && /\s\(/.test(name) && (!addr || addr === name)) {
        const idx = name.indexOf(' (');
        const extractedAddr = name.slice(idx + 2).replace(/\)\s*$/, '').trim();
        const extractedName = name.slice(0, idx).trim();
        name = extractedName;
        if (!addr || addr === el.dataset.name) addr = extractedAddr;
      }
      const cleanAddr = addr.replace(/\s*\([^)]*\)/g, '').trim();

      const searchByName = () => new Promise(res => {
        if (!name) return res(null);
        places.keywordSearch(name, (r, s) => {
          if (s === kakao.maps.services.Status.OK && r[0]) {
            res({ x: r[0].x, y: r[0].y });
          } else {
            res(null);
          }
        });
      });

      const searchByAddr = () => new Promise(res => {
        if (!cleanAddr) return res(null);
        geocoder.addressSearch(cleanAddr, (r, s) => {
          if (s === kakao.maps.services.Status.OK && r[0]) {
            res({ x: r[0].x, y: r[0].y });
          } else {
            res(null);
          }
        });
      });

      // 장소명 우선 검색 → 실패 시 주소 검색 폴백
      const resolveLocation = async () => (await searchByName()) || (await searchByAddr());

      resolveLocation().then(loc => {
        el.setAttribute('data-kakao-ready', loc ? '1' : 'notfound');
        if (!loc) {
          el.innerHTML = '<div class="venue__map-msg">지도 위치를 찾을 수 없습니다.</div>';
          return;
        }
        const latlng = new kakao.maps.LatLng(Number(loc.y), Number(loc.x));
        el.innerHTML = '';
        const map = new kakao.maps.Map(el, { center: latlng, level: 4, draggable: true });
        new kakao.maps.Marker({ position: latlng, map });
        kakao.maps.event.addListener(map, 'click', () => {
          const q = encodeURIComponent(name || cleanAddr);
          window.open(`https://map.kakao.com/link/map/${q},${loc.y},${loc.x}`, '_blank', 'noopener');
        });
        setTimeout(() => {
          map.relayout();
          map.setCenter(latlng);
        }, 50);
      });
    });
  }

  // ---------- Preview ----------
  function renderPreview() {
    if (!state.draft) { navigate('create'); return; }
    setHeader({ title: '부고장 미리보기', back: true, menu: false });
    const d = state.draft;
    viewEl.innerHTML = obituaryHTML(d, { preview: true });
    initFuneralMaps(viewEl);
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
    initFuneralMaps(viewEl);
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
          <div class="head-sub">${fmtDate(f.deathAt?.slice(0, 10) || d.death)} ${escapeHtml(f.deathTerm || '별세')}</div>
        </header>
        <div class="obituary__body">

          <section class="card">
            <div class="card__title"><span class="ico">⚘</span>고인 정보</div>
            <div class="deceased">
              ${photoBlock}
              <div>
                <div class="deceased__name">故 ${escapeHtml(d.name || '')}님</div>
                <div class="deceased__meta">
                  ${[fmtDate(f.deathAt?.slice(0, 10) || d.death) + ' ' + (f.deathTerm || '별세'), ageDisplay(d.birth)]
        .filter(Boolean).join(' · ')}
                </div>
                ${d.showTitle && (d.titles || []).some(t => t && t.trim()) ? `<div class="deceased__roles">${(d.titles || []).filter(t => t && t.trim()).map(escapeHtml).join('<br>')}</div>` : ''}
              </div>
            </div>
          </section>

          ${o.mourners.length || o.notice ? `
            <section class="card">
              <div class="card__title"><span class="ico">⚘</span>상주 정보</div>
              ${o.mourners.length ? `
                <dl class="def-list">
                  ${o.mourners.map(m => `<div class="row"><dt>${escapeHtml(m.relation || '')}</dt><dd>${escapeHtml(m.name || '')}</dd></div>`).join('')}
                </dl>
              ` : ''}
              ${o.notice ? `<div class="message-block mourner-notice">${escapeHtml(o.notice)}</div>` : ''}
            </section>
          `: ''}

          <section class="card">
            <div class="card__title"><span class="ico">⚘</span>장례 일정</div>
            <dl class="def-list">
              <div class="row"><dt>${escapeHtml(f.deathTerm || '별세')}일</dt><dd>${fmtDate(f.deathAt?.slice(0, 10))}</dd></div>
              <div class="row"><dt>입관일시</dt><dd>${f.encoffinAt ? (f.encoffinTimeUndecided ? fmtDate(f.encoffinAt.slice(0, 10)) : fmtDateTime(f.encoffinAt)) : '미정'}</dd></div>
              <div class="row"><dt>발인일시</dt><dd>${f.carryDateUndecided ? '미정' : (f.carryAt ? (f.carryTimeUndecided ? fmtDate(f.carryAt.slice(0, 10)) : fmtDateTime(f.carryAt)) : '미정')}</dd></div>
              <div class="row"><dt>장지</dt><dd>${f.place ? escapeHtml(f.place) : '미정'}</dd></div>
            </dl>
          </section>

          ${(f.funeralHomeName || f.funeralHomeAddr || f.funeralHome) ? (() => {
            const h = f.funeralHomeData;
            const name = f.funeralHomeName || h?.name || f.funeralHome;
            const addr = f.funeralHomeAddr || h?.addr || '';
            const tel = f.funeralHomePhone || h?.telno || '';
            const hp = h?.homepageUrl || '';
            const room = f.funeralHomeRoom || '';
            const addrForCopy = addr || f.funeralHome || '';
            return `
            <section class="card">
              <div class="card__title"><span class="ico">⚘</span>장례식장</div>
              <div class="venue">
                <div class="venue__name">${escapeHtml(name)}${room ? ` · ${escapeHtml(room)}` : ''}</div>
                ${addrForCopy ? `
                  <div class="venue__row">
                    <span class="venue__addr">${escapeHtml(addrForCopy)}</span>
                    <button type="button" class="icon-btn" aria-label="주소 복사" data-copy="${escapeHtml(addrForCopy)}" data-toast="주소가 복사되었습니다.">
                      <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/></svg>
                    </button>
                  </div>
                ` : ''}
                ${tel ? `
                  <div class="venue__row">
                    <a class="text-btn text-btn--inline" href="tel:${escapeHtml(tel.replace(/[^0-9+]/g, ''))}">${escapeHtml(tel)}</a>
                  </div>
                ` : ''}
                ${hp ? `<div class="venue__hp"><a href="${/^https?:\/\//.test(hp) ? escapeHtml(hp) : 'https://' + escapeHtml(hp)}" target="_blank" rel="noreferrer noopener">홈페이지</a></div>` : ''}
              </div>
              ${addr ? `<div class="venue__map" data-kakao-map data-addr="${escapeHtml(addr)}" data-name="${escapeHtml(name)}">
                <div class="venue__map-msg">지도 불러오는 중…</div>
              </div>` : ''}
            </section>
          `;})() : ''}

          ${!o.noDonation && o.donations.some(x => x.bank || x.account) ? `
            <section class="card">
              <div class="card__title"><span class="ico">⚘</span>마음을 전하는 곳</div>
              ${o.donations.filter(x => x.bank || x.account).map(x => `
                <div class="donation-item">
                  ${(x.relation || x.owner) ? `
                    <div class="donation-item__row">
                      ${x.relation ? `<span class="donation-item__label">${escapeHtml(x.relation)}</span>` : ''}
                      ${x.owner ? `<span class="donation-item__value">${escapeHtml(x.owner)}</span>` : ''}
                    </div>
                  ` : ''}
                  ${(x.bank || x.account) ? `
                    <div class="donation-item__row donation-item__row--account">
                      ${x.bank ? `<span class="donation-item__bank">${escapeHtml(x.bank)}</span>` : ''}
                      ${x.account ? `<span class="donation-item__account">${escapeHtml(x.account)}</span>` : ''}
                      ${x.account ? `
                        <button type="button" class="icon-btn" aria-label="계좌 번호 복사" data-copy="${escapeHtml(x.account)}" data-toast="계좌 번호가 복사되었습니다.">
                          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/></svg>
                        </button>
                      ` : ''}
                    </div>
                  ` : ''}
                </div>
              `).join('')}
            </section>
          `: ''}

          ${o.messagesEnabled ? `
            <section class="card">
              <div class="card__title" style="display:flex;justify-content:space-between;align-items:center;">
                <span><span class="ico">⚘</span>추모 메시지</span>
                <div style="display:flex;gap:8px;align-items:center;">
                  <button class="card__action" id="writeMsg">메시지 작성</button>
                  ${!preview ? `<button class="btn--text" id="goMessages" style="font-size:12px;">더보기 ›</button>` : ''}
                </div>
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
  const isTouchDevice = () => window.matchMedia?.('(pointer: coarse)').matches;
  document.addEventListener('click', (e) => {
    const copy = e.target.closest('[data-copy]');
    if (copy) {
      // tel: 링크는 터치 기기(모바일)에서만 네이티브 전화걸기로 처리, 데스크톱에서는 복사
      const isTelLink = copy.tagName === 'A' && (copy.getAttribute('href') || '').startsWith('tel:');
      if (isTelLink && isTouchDevice()) return;
      if (isTelLink) e.preventDefault();
      const v = copy.dataset.copy;
      const msg = copy.dataset.toast || '복사되었습니다.';
      const done = () => toast(msg);
      const fallback = () => {
        try {
          const ta = document.createElement('textarea');
          ta.value = v; ta.style.position = 'fixed'; ta.style.opacity = '0';
          document.body.appendChild(ta); ta.select(); document.execCommand('copy');
          document.body.removeChild(ta);
        } catch {}
        done();
      };
      if (navigator.clipboard?.writeText) {
        navigator.clipboard.writeText(v).then(done, fallback);
      } else {
        fallback();
      }
    }
    const goMsg = e.target.closest('#goMessages');
    if (goMsg) navigate('messages', { id: state.activeObituaryId });

    const writeMsg = e.target.closest('#writeMsg');
    if (writeMsg) navigate('message-write', { id: state.activeObituaryId });

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

  // ---------- URL hash routing ----------
  function syncFromHash() {
    const { route, params } = routeFromHash(location.hash);
    state.route = route;
    state.params = params;
    render();
    window.scrollTo({ top: 0, behavior: 'instant' });
  }
  window.addEventListener('popstate', syncFromHash);
  window.addEventListener('hashchange', syncFromHash);

  // ---------- Boot ----------
  syncFromHash();
})();
