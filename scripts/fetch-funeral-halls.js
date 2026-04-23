import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

const SERVICE_KEY = process.env.SERVICE_KEY;
const API_URL = process.env.API_URL;

if (!SERVICE_KEY || !API_URL) {
  console.error('SERVICE_KEY 또는 API_URL이 .env에 설정되어 있지 않습니다.');
  process.exit(1);
}

const NUM = 500;

async function fetchPage(pageNo) {
  const url = new URL(API_URL);
  url.searchParams.set('serviceKey', SERVICE_KEY);
  url.searchParams.set('pageNo', String(pageNo));
  url.searchParams.set('numOfRows', String(NUM));
  url.searchParams.set('apiType', 'JSON');
  const r = await fetch(url.toString(), { headers: { Accept: 'application/json' } });
  if (!r.ok) throw new Error(`HTTP ${r.status} for page ${pageNo}`);
  return r.json();
}

console.log('페이지 1 불러오는 중...');
const first = await fetchPage(1);
const total = Number(first.totalCount || 0);
const pageCount = Math.max(1, Math.ceil(total / NUM));
console.log(`전체 ${total}건, ${pageCount}개 페이지 예상`);

let items = Array.isArray(first.items) ? first.items : [];
for (let p = 2; p <= pageCount; p++) {
  console.log(`페이지 ${p}/${pageCount} 불러오는 중...`);
  const d = await fetchPage(p);
  items = items.concat(Array.isArray(d.items) ? d.items : []);
}

const slim = items.map(it => ({
  fcltNm: it.fcltNm || '',
  addr: it.addr || '',
  ctpv: it.ctpv || '',
  sigungu: it.sigungu || '',
  telno: it.telno || '',
  gubun: it.gubun || '',
}));

const outPath = path.join(ROOT, 'data', 'funeral-halls.json');
await fs.mkdir(path.dirname(outPath), { recursive: true });
await fs.writeFile(
  outPath,
  JSON.stringify({ updatedAt: new Date().toISOString(), total: slim.length, items: slim })
);

console.log(`\n✓ ${slim.length}건을 ${path.relative(ROOT, outPath)} 에 저장했습니다.`);
