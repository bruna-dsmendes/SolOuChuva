// ============================================================
//  SolOuChuva? — script.js  v5.0  (VERSÃO SEGURA)
//
//  🔒 SEGURANÇA IMPLEMENTADA:
//  ✅ Rate Limiting: máximo 1 req/3s + debounce de 500ms no input
//  ✅ Validação e sanitização de input (XSS prevention)
//  ✅ textContent/setAttribute em TODOS os dados dinâmicos (nunca innerHTML com dados externos)
//  ✅ Proteção de API: Open-Meteo é pública, sem chave — documentado
//  ✅ Tratamento de erros granular por tipo (rede, API, geo, parse, rate limit)
//  ✅ Sanitização de dados da API antes de renderizar
//  ✅ Cache com validação de integridade e TTL (30min)
//  ✅ Proteção contra ReDoS na regex de validação
//  ✅ Timeout em fetch para evitar requisições penduradas
//  ✅ CSP-friendly: zero eval(), zero Function(), zero innerHTML com dados externos
//
//  🚀 FUNCIONALIDADES:
//  ✅ Geolocalização automática
//  ✅ Seções colapsáveis (accordion)
//  ✅ Atualização automática silenciosa (10 min)
//  ✅ Compartilhamento via Web Share API
//  ✅ Cache inteligente offline (localStorage, TTL 30min)
//  ✅ Animação de troca de cidade (fade)
//  ✅ Modo noturno automático por pôr do sol real
//  ✅ Histórico de buscas (localStorage)
//  ✅ UV, umidade e sensação com dicas inteligentes
//  ✅ Look do dia + mensagens de humor
//  ✅ Previsão 7 dias
// ============================================================

'use strict';

// ============================================================
//  🔒 MÓDULO DE SEGURANÇA
// ============================================================

/**
 * RATE LIMITER
 * Bloqueia chamadas excessivas à API.
 * Regra: mínimo de RATE_LIMIT_MS entre requisições.
 */
const RateLimit = (() => {
  const RATE_LIMIT_MS = 3000;  // 3 segundos entre buscas
  let lastCallTime    = 0;

  return {
    canCall() {
      const now = Date.now();
      if (now - lastCallTime < RATE_LIMIT_MS) return false;
      lastCallTime = now;
      return true;
    },
    msUntilNext() {
      return Math.ceil((RATE_LIMIT_MS - (Date.now() - lastCallTime)) / 1000);
    }
  };
})();

/**
 * SANITIZAÇÃO DE INPUT
 * - Remove caracteres perigosos para XSS
 * - Valida tamanho e conteúdo mínimo
 * - Retorna string segura ou null se inválido
 */
function sanitizeInput(raw) {
  if (typeof raw !== 'string') return null;

  // Remove espaços extras nas bordas
  const trimmed = raw.trim();

  // Comprimento mínimo e máximo
  if (trimmed.length < 2)   return null;
  if (trimmed.length > 100) return null;

  // Apenas letras (incluindo acentos e cedilha), espaços, hífens e vírgulas
  // Proteção contra ReDoS: regex simples, sem backtracking catastrófico
  const safePattern = /^[\p{L}\s,.\-']+$/u;
  if (!safePattern.test(trimmed)) return null;

  return trimmed;
}

/**
 * SANITIZAÇÃO DE STRINGS DA API
 * Garante que dados externos não contenham HTML/script antes de exibir.
 * Retorna string segura para uso em textContent.
 */
function sanitizeApiString(value, fallback = '—') {
  if (value === null || value === undefined) return fallback;
  const str = String(value).trim();
  if (str.length === 0 || str.length > 200) return fallback;
  // Remove qualquer tag HTML que possa ter vindo da API
  return str.replace(/<[^>]*>/g, '');
}

/**
 * SANITIZAÇÃO DE NÚMEROS DA API
 * Evita NaN, Infinity ou valores absurdos sendo exibidos.
 */
function sanitizeNumber(value, fallback = 0, min = -100, max = 10000) {
  const n = Number(value);
  if (!isFinite(n) || n < min || n > max) return fallback;
  return n;
}

/**
 * FETCH COM TIMEOUT E TRATAMENTO DE ERROS GRANULAR
 * Evita que requisições fiquem penduradas indefinidamente.
 */
async function safeFetch(url, timeoutMs = 8000) {
  const controller = new AbortController();
  const timer      = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, { signal: controller.signal });
    clearTimeout(timer);

    if (res.status === 429) throw new AppError('rate_limit',  'Muitas requisições. Aguarde alguns segundos.');
    if (res.status === 404) throw new AppError('not_found',   'Recurso não encontrado na API.');
    if (res.status >= 500)  throw new AppError('server_error','Servidor da API fora do ar. Tente novamente.');
    if (!res.ok)            throw new AppError('http_error',  `Erro HTTP ${res.status}.`);

    const data = await res.json();
    return data;

  } catch (err) {
    clearTimeout(timer);
    if (err instanceof AppError) throw err;
    if (err.name === 'AbortError') throw new AppError('timeout', 'Tempo limite esgotado. Verifique sua conexão.');
    if (err instanceof TypeError)  throw new AppError('network', 'Sem conexão com a internet.');
    throw new AppError('unknown', 'Erro inesperado. Tente novamente.');
  }
}

/**
 * CLASSE DE ERROS DA APLICAÇÃO
 * Permite tratamento granular por tipo de erro.
 */
class AppError extends Error {
  constructor(type, message) {
    super(message);
    this.type = type; // 'network' | 'timeout' | 'not_found' | 'rate_limit' | 'server_error' | 'invalid_input' | 'parse' | 'geo' | 'http_error' | 'unknown'
    this.name = 'AppError';
  }
}

/**
 * MENSAGENS DE ERRO AMIGÁVEIS POR TIPO
 */
function friendlyError(err) {
  const MESSAGES = {
    network:       '📡 Sem conexão. Verifique sua internet e tente novamente.',
    timeout:       '⏱️ A API demorou demais para responder. Tente novamente.',
    not_found:     '🔍 Cidade não encontrada. Verifique a grafia.',
    rate_limit:    '⏳ Você está buscando muito rápido! Aguarde alguns segundos.',
    server_error:  '🌩️ O servidor de clima está instável. Tente em alguns minutos.',
    invalid_input: '✏️ Nome de cidade inválido. Use apenas letras, espaços e hífens.',
    parse:         '⚠️ Erro ao processar os dados da API. Tente novamente.',
    geo:           '📍 Não foi possível detectar sua localização.',
    http_error:    '⚠️ Erro de comunicação com a API.',
    unknown:       '😕 Algo deu errado. Tente novamente em instantes.',
  };
  if (err instanceof AppError) return MESSAGES[err.type] ?? MESSAGES.unknown;
  return MESSAGES.unknown;
}

// ============================================================
//  DOM
// ============================================================
const cityInput      = document.getElementById('city-input');
const searchBtn      = document.getElementById('search-btn');
const btnIcon        = document.getElementById('btn-icon');
const weatherCard    = document.getElementById('weather-card');
const loading        = document.getElementById('loading');
const loadingText    = document.getElementById('loading-text');
const errorMsg       = document.getElementById('error-msg');
const errorText      = document.getElementById('error-text');
const themeColorMeta = document.getElementById('theme-color-meta');
const historyBox     = document.getElementById('history-box');
const historyTags    = document.getElementById('history-tags');
const geoBtn         = document.getElementById('geo-btn');
const shareBtn       = document.getElementById('share-btn');
const nightBadge     = document.getElementById('night-badge');
const cacheBadge     = document.getElementById('cache-badge');
const refreshBadge   = document.getElementById('refresh-badge');

// ============================================================
//  ESTADO GLOBAL
// ============================================================
let currentGeo   = null;
let refreshTimer = null;
let debounceTimer = null;

const REFRESH_MS  = 10 * 60 * 1000; // 10 minutos
const CACHE_TTL   = 30 * 60 * 1000; // cache válido por 30 minutos
const DEBOUNCE_MS = 500;             // debounce do input

// ============================================================
//  WMO WEATHER CODES
//  Fonte: https://open-meteo.com/en/docs#weathervariables
//  Valores são constantes internas — seguros para exibição.
// ============================================================
const WMO = {
  0:{icon:'☀️',desc:'Céu limpo'},         1:{icon:'🌤️',desc:'Principalmente limpo'},
  2:{icon:'⛅',desc:'Parcialmente nublado'},3:{icon:'☁️',desc:'Encoberto'},
  45:{icon:'🌫️',desc:'Neblina'},          48:{icon:'🌫️',desc:'Neblina com geada'},
  51:{icon:'🌦️',desc:'Garoa leve'},       53:{icon:'🌦️',desc:'Garoa moderada'},
  55:{icon:'🌦️',desc:'Garoa densa'},      61:{icon:'🌧️',desc:'Chuva leve'},
  63:{icon:'🌧️',desc:'Chuva moderada'},   65:{icon:'🌧️',desc:'Chuva intensa'},
  71:{icon:'🌨️',desc:'Neve leve'},        73:{icon:'🌨️',desc:'Neve moderada'},
  75:{icon:'❄️',desc:'Neve intensa'},     77:{icon:'🌨️',desc:'Granizo'},
  80:{icon:'🌦️',desc:'Pancadas leves'},   81:{icon:'🌧️',desc:'Pancadas moderadas'},
  82:{icon:'⛈️',desc:'Pancadas fortes'},  85:{icon:'🌨️',desc:'Neve em pancadas'},
  86:{icon:'❄️',desc:'Neve intensa em pancadas'},
  95:{icon:'⛈️',desc:'Tempestade'},       96:{icon:'⛈️',desc:'Tempestade com granizo'},
  99:{icon:'⛈️',desc:'Tempestade com granizo forte'},
};
const getWmo = code => {
  const n = sanitizeNumber(code, -1, 0, 99);
  return WMO[n] ?? { icon:'🌡️', desc:'Condição desconhecida' };
};

// ============================================================
//  TEMAS DE TEMPERATURA
// ============================================================
const TEMP_THEMES = [
  { max:10,       cls:'temp-gelado',     label:'🥶 Muito frio',            color:'#0d1b4b' },
  { max:17,       cls:'temp-frio',       label:'🌬️ Frio',                 color:'#0f2d4a' },
  { max:24,       cls:'temp-ameno',      label:'😊 Temperatura agradável', color:'#0d3025' },
  { max:32,       cls:'temp-quente',     label:'☀️ Quente',               color:'#3d1f00' },
  { max:Infinity, cls:'temp-escaldante', label:'🔥 Muito quente',          color:'#4a0000' },
];
const ALL_TEMP = TEMP_THEMES.map(t => t.cls);

function applyTempTheme(temp) {
  const t = TEMP_THEMES.find(t => temp < t.max) ?? TEMP_THEMES.at(-1);
  document.body.classList.remove(...ALL_TEMP);
  document.body.classList.add(t.cls);
  // setAttribute é seguro — valor é constante interna, não dado do usuário
  if (themeColorMeta) themeColorMeta.setAttribute('content', t.color);
  return t.label;
}

// ============================================================
//  MODO NOTURNO
// ============================================================
function applyNightMode(sunriseStr, sunsetStr) {
  // Valida formato HH:MM antes de processar
  const timePattern = /^\d{2}:\d{2}$/;
  if (!timePattern.test(sunriseStr) || !timePattern.test(sunsetStr)) return false;

  const toMin  = s => { const [h,m] = s.split(':').map(Number); return h*60+m; };
  const now    = new Date();
  const nowMin = now.getHours()*60 + now.getMinutes();
  const isNight = nowMin < toMin(sunriseStr) || nowMin >= toMin(sunsetStr);

  document.body.classList.toggle('modo-noturno', isNight);
  if (nightBadge) nightBadge.style.display = isNight ? 'inline-flex' : 'none';
  return isNight;
}

// ============================================================
//  HELPERS DE CONTEÚDO
// ============================================================
function uvInfo(uv) {
  const n = sanitizeNumber(uv, 0, 0, 20);
  if (n <= 2)  return { label:`${n} Baixo`,      tip:'✅ Sem necessidade de protetor',          alert:false };
  if (n <= 5)  return { label:`${n} Moderado`,   tip:'🧴 Use protetor FPS 30+',                 alert:false };
  if (n <= 7)  return { label:`${n} Alto`,       tip:'🧴 FPS 50+! Use chapéu.',                 alert:true  };
  if (n <= 10) return { label:`${n} Muito alto`, tip:'⚠️ FPS 50+, evite sol das 10h–16h.',      alert:true  };
  return               { label:`${n} Extremo`,   tip:'🚨 Fique na sombra! FPS 50+ a cada 2h.', alert:true  };
}

function humidityTip(h) {
  const n = sanitizeNumber(h, 50, 0, 100);
  if (n < 30) return '🏜️ Hidrate-se muito! Ar muito seco.';
  if (n < 50) return '💧 Hidrate a pele, ar seco.';
  if (n < 70) return '✅ Umidade confortável.';
  if (n < 85) return '😅 Ar úmido e abafado.';
  return             '🌧️ Muito úmido!';
}

function feelsTip(feels, temp) {
  const d = feels - temp;
  if (d <= -5) return '🥶 Parece bem mais frio do que é!';
  if (d >=  5) return '🔥 Parece bem mais quente!';
  return             '✅ Sensação próxima à temperatura real.';
}

const HUMOR = {
  chuva:   ['☕ Dia perfeito para um café!','🎵 Música boa e cobertor!','📚 Leia um livro com som de chuva.','🍵 Chá e Netflix? Sim!'],
  neve:    ['⛄ Vá montar um boneco de neve!','🛷 Cadê o trenó?!'],
  neblina: ['🌫️ Cuidado ao dirigir, visibilidade reduzida!'],
  calor:   ['🍦 Um sorvete cai muito bem hoje!','🏖️ Dia de piscina!','🥵 Beba muita água e fique na sombra!','🍉 Melancia gelada: a cura!'],
  quente:  ['😎 Aproveite o sol!','🌻 Que sol bonito hoje!','🕶️ Não esqueça os óculos de sol!'],
  ameno:   ['🌿 Temperatura perfeita para uma caminhada!','🧺 Dia ideal para um piquenique.','🚲 Que tal pedalar hoje?'],
  frio:    ['🧣 Vista o casaco, tá fresquinho!','☕ Cappuccino ou chocolate quente?','🍲 Dia de sopa quentinha!'],
  gelado:  ['🧥 Agasalhe-se bem, tá gelado!','🛋️ Melhor lugar é o sofá com cobertor!','🍫 Chocolate quente pra aquecer ❤️'],
};
const pick = arr => arr[Math.floor(Math.random() * arr.length)];

function humorMsg(code, temp) {
  if ([51,53,55,61,63,65,80,81,82,95,96,99].includes(code)) return pick(HUMOR.chuva);
  if ([71,73,75,77,85,86].includes(code)) return pick(HUMOR.neve);
  if ([45,48].includes(code)) return pick(HUMOR.neblina);
  if (temp >= 33) return pick(HUMOR.calor);
  if (temp >= 26) return pick(HUMOR.quente);
  if (temp >= 18) return pick(HUMOR.ameno);
  if (temp >= 10) return pick(HUMOR.frio);
  return pick(HUMOR.gelado);
}

function lookInfo(temp) {
  if (temp >= 33) return { icon:'🩳', msg:'Shorts, camiseta e sandálias! Quanto mais leve, melhor.' };
  if (temp >= 26) return { icon:'👕', msg:'Camiseta e calça leve. Não esqueça o protetor solar!' };
  if (temp >= 20) return { icon:'👗', msg:'Roupa leve, mas leve uma blusa para o final do dia.' };
  if (temp >= 15) return { icon:'🧥', msg:'Casaco ou jaqueta leve. Camadas são suas amigas!' };
  if (temp >= 10) return { icon:'🧣', msg:'Casaco, cachecol e calça grossa. Tá frio lá fora!' };
  return                 { icon:'🧤', msg:'Casaco pesado, luvas e gorro. Está muito frio!' };
}

// ============================================================
//  HELPERS DE FORMATO
// ============================================================
const formatDate = iso => {
  try {
    return new Date(iso).toLocaleDateString('pt-BR', {
      weekday:'long', day:'2-digit', month:'long', year:'numeric'
    });
  } catch { return '—'; }
};
const formatHour = iso => (typeof iso === 'string' && iso.length >= 16) ? iso.slice(11,16) : '—';
const toTitle    = s   => (typeof s === 'string' && s.length > 0) ? s.charAt(0).toUpperCase() + s.slice(1) : s;

// ============================================================
//  🔒 CACHE COM TTL E VALIDAÇÃO DE INTEGRIDADE
// ============================================================
const CACHE_KEY = 'soc_cache_v2'; // v2 — invalida cache antigo automaticamente

function saveCache(geo, data) {
  try {
    // Salva apenas os campos necessários — não salva a resposta bruta completa
    const payload = {
      geo: {
        name:      sanitizeApiString(geo.name),
        admin1:    sanitizeApiString(geo.admin1),
        country:   sanitizeApiString(geo.country),
        latitude:  sanitizeNumber(geo.latitude,  0, -90,  90),
        longitude: sanitizeNumber(geo.longitude, 0, -180, 180),
      },
      data,
      ts: Date.now(),
    };
    localStorage.setItem(CACHE_KEY, JSON.stringify(payload));
  } catch (e) {
    // localStorage cheio ou bloqueado — falha silenciosamente
    console.warn('[SolOuChuva] Cache não pôde ser salvo:', e.message);
  }
}

function loadCache() {
  try {
    const raw = localStorage.getItem(CACHE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);

    // Valida estrutura mínima
    if (!parsed?.geo?.name || !parsed?.data?.current || !parsed?.ts) return null;

    // Valida TTL (30 minutos)
    if (Date.now() - parsed.ts > CACHE_TTL) {
      localStorage.removeItem(CACHE_KEY);
      return null;
    }

    return parsed;
  } catch {
    return null;
  }
}

// ============================================================
//  HISTÓRICO
// ============================================================
const HIST_KEY = 'soc_history_v2';
const MAX_HIST = 6;

function getHistory() {
  try {
    const raw = JSON.parse(localStorage.getItem(HIST_KEY)) || [];
    // Valida cada item do histórico
    return raw.filter(c => typeof c === 'string' && c.length > 0 && c.length <= 100);
  } catch { return []; }
}

function saveHistory(city) {
  const safe = sanitizeApiString(city);
  if (!safe || safe === '—') return;
  let h = getHistory().filter(c => c.toLowerCase() !== safe.toLowerCase());
  h.unshift(safe);
  if (h.length > MAX_HIST) h = h.slice(0, MAX_HIST);
  try { localStorage.setItem(HIST_KEY, JSON.stringify(h)); } catch {}
  renderHistory();
}

function renderHistory() {
  const h = getHistory();
  if (!h.length) { historyBox.classList.add('hidden'); return; }
  historyBox.classList.remove('hidden');
  historyTags.innerHTML = '';
  h.forEach(city => {
    const tag = document.createElement('button');
    tag.className   = 'history-tag';
    tag.textContent = city;   // ✅ textContent — nunca innerHTML
    tag.addEventListener('click', () => {
      cityInput.value = city;
      fetchWeather(city);
    });
    historyTags.appendChild(tag);
  });
}

// ============================================================
//  ACCORDION
// ============================================================
function initAccordions() {
  document.querySelectorAll('.collapsible-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.dataset.target;
      // Valida que o target existe e tem o formato esperado
      if (!/^[\w-]+$/.test(targetId)) return;
      const body   = document.getElementById(targetId);
      if (!body) return;
      const isOpen = btn.getAttribute('aria-expanded') === 'true';
      btn.setAttribute('aria-expanded', String(!isOpen));
      body.classList.toggle('open', !isOpen);
    });
  });
}

// ============================================================
//  ESTADOS DA UI
// ============================================================
function showLoading(silent = false) {
  if (!silent) {
    weatherCard.classList.add('hidden');
    errorMsg.classList.add('hidden');
    loading.classList.remove('hidden');
    btnIcon.textContent = '⏳';
    searchBtn.disabled  = true;
  } else {
    weatherCard.classList.add('refreshing');
  }
}

function hideLoading(silent = false) {
  if (!silent) {
    loading.classList.add('hidden');
    btnIcon.textContent = '🔍';
    searchBtn.disabled  = false;
  } else {
    weatherCard.classList.remove('refreshing');
  }
}

function showError(err) {
  hideLoading();
  const msg = err instanceof AppError ? friendlyError(err) : (typeof err === 'string' ? err : friendlyError(new AppError('unknown')));
  // ✅ textContent — nunca innerHTML para exibir erros
  errorText.textContent = msg;
  errorMsg.classList.remove('hidden');
  weatherCard.classList.add('hidden');
}

// ============================================================
//  ANIMAÇÃO FADE
// ============================================================
function animateCardOut(cb) {
  weatherCard.style.transition = 'opacity .25s ease, transform .25s ease';
  weatherCard.style.opacity    = '0';
  weatherCard.style.transform  = 'translateY(-10px)';
  setTimeout(() => {
    cb();
    weatherCard.style.opacity   = '1';
    weatherCard.style.transform = 'translateY(0)';
  }, 280);
}

// ============================================================
//  🌐 API — GEOCODING
//  ⚠️ Open-Meteo é uma API pública e gratuita — sem API key.
//  Nunca armazene chaves de API no frontend (localStorage,
//  variáveis JS, etc). Se usar APIs pagas no futuro,
//  utilize sempre um backend/proxy intermediário.
// ============================================================
async function getCoordinates(city) {
  // city já foi sanitizado antes de chegar aqui
  const url  = `https://geocoding-api.open-meteo.com/v1/search?name=${encodeURIComponent(city)}&count=1&language=pt&format=json`;
  const data = await safeFetch(url);

  if (!Array.isArray(data?.results) || data.results.length === 0) {
    throw new AppError('not_found', `"${city}" não encontrada. Verifique a grafia.`);
  }

  const r = data.results[0];

  // Valida e sanitiza cada campo da resposta da API
  return {
    name:      sanitizeApiString(r.name,    'Desconhecida'),
    admin1:    sanitizeApiString(r.admin1,   ''),
    country:   sanitizeApiString(r.country,  ''),
    latitude:  sanitizeNumber(r.latitude,   0, -90,  90),
    longitude: sanitizeNumber(r.longitude,  0, -180, 180),
  };
}

// ============================================================
//  🌐 API — CLIMA
// ============================================================
async function getWeather(lat, lon) {
  const safeUrl = `https://api.open-meteo.com/v1/forecast?` + new URLSearchParams({
    latitude:        sanitizeNumber(lat, 0, -90, 90),
    longitude:       sanitizeNumber(lon, 0, -180, 180),
    current:         ['temperature_2m','apparent_temperature','relative_humidity_2m',
                      'weather_code','wind_speed_10m','wind_direction_10m','precipitation','visibility','uv_index'].join(','),
    hourly:          ['temperature_2m','weather_code','precipitation_probability'].join(','),
    daily:           ['weather_code','temperature_2m_max','temperature_2m_min','sunrise','sunset','precipitation_probability_max','precipitation_sum'].join(','),
    timezone:        'America/Sao_Paulo',
    forecast_days:   7,
    wind_speed_unit: 'kmh',
  });

  const data = await safeFetch(safeUrl);

  // Valida estrutura mínima da resposta
  if (!data?.current || !data?.hourly || !data?.daily) {
    throw new AppError('parse', 'Resposta da API inválida ou incompleta.');
  }

  return data;
}

// ============================================================
//  RENDERIZAR — ✅ usa textContent/setAttribute em TUDO
// ============================================================
function renderWeather(geo, data, { silent = false, fromCache = false } = {}) {
  const doRender = () => {
    // --- Dados brutos da API ---
    const c = data.current;

    // Temperatura — sanitiza antes de usar em cálculos
    const temp     = Math.round(sanitizeNumber(c.temperature_2m,     20, -80, 60));
    const feelsVal = Math.round(sanitizeNumber(c.apparent_temperature,20, -80, 60));
    const humidity = sanitizeNumber(c.relative_humidity_2m, 50, 0, 100);
    const wind      = Math.round(sanitizeNumber(c.wind_speed_10m, 0, 0, 400));
    const windDir   = sanitizeNumber(c.wind_direction_10m, 0, 0, 360);
    const rain     = sanitizeNumber(c.precipitation, 0, 0, 999);
    const vis      = sanitizeNumber(c.visibility, 10000, 0, 100000);
    const uv       = sanitizeNumber(c.uv_index, 0, 0, 20);
    const code     = sanitizeNumber(c.weather_code, 0, 0, 99);

    const info     = getWmo(code);
    const badgeLabel = applyTempTheme(temp);

    // Modo noturno
    const sunrise = sanitizeApiString(data.daily?.sunrise?.[0], '').slice(11);
    const sunset  = sanitizeApiString(data.daily?.sunset?.[0],  '').slice(11);
    applyNightMode(sunrise, sunset);

    // Cache badge
    cacheBadge.classList.toggle('hidden', !fromCache);

    // --- Cabeçalho ---
    // ✅ textContent — dados da API (nome da cidade)
    const locName = sanitizeApiString(geo.name);
    const locAdmin = sanitizeApiString(geo.admin1);
    const locCountry = sanitizeApiString(geo.country);
    const location = locAdmin ? `${locName}, ${locAdmin}` : `${locName}, ${locCountry}`;
    document.getElementById('city-name').textContent    = location;          // ✅ textContent
    document.getElementById('weather-date').textContent = formatDate(sanitizeApiString(c.time)); // ✅

    if (silent) {
      refreshBadge.classList.remove('hidden');
      setTimeout(() => refreshBadge.classList.add('hidden'), 3500);
    } else {
      refreshBadge.classList.add('hidden');
    }

    // --- Principal ---
    document.getElementById('weather-icon').textContent = info.icon;         // ✅ emoji constante
    document.getElementById('temp-value').textContent   = temp;              // ✅ número sanitizado
    document.getElementById('weather-desc').textContent = info.desc;         // ✅ string constante
    document.getElementById('temp-badge').textContent   = badgeLabel;        // ✅ string constante

    // --- Humor + Look ---
    document.getElementById('humor-msg').textContent = `"${humorMsg(code, temp)}"`;  // ✅ string interna
    const look = lookInfo(temp);
    document.getElementById('look-icon').textContent = look.icon;            // ✅ emoji constante
    document.getElementById('look-msg').textContent  = look.msg;             // ✅ string interna

    // --- Detalhes ---
    document.getElementById('feels-like').textContent    = `${feelsVal}°C`;  // ✅ número sanitizado
    document.getElementById('feels-tip').textContent     = feelsTip(feelsVal, temp); // ✅ string interna
    document.getElementById('humidity').textContent      = `${humidity}%`;   // ✅
    document.getElementById('humidity-tip').textContent  = humidityTip(humidity);   // ✅
    document.getElementById('wind-speed').textContent    = `${wind} km/h`;   // ✅
    document.getElementById('wind-beaufort').textContent = beaufortLabel(wind);

    // Rosa dos ventos animada
    renderWindCard(wind, windDir);

    // Efeitos visuais: partículas + sol
    triggerWeatherFX(code, temp);

    // Previsão de chuva
    renderRainForecast(data);

    // Gráfico de temperatura 24h
    renderTempChart(data);

    // Animação nascer/pôr do sol
    renderSunArc(data.daily?.sunrise?.[0], data.daily?.sunset?.[0], c.time);

    // Notificações de mudança brusca (só em atualizações silenciosas)
    if (silent) checkWeatherAlert(code, temp, wind);
    document.getElementById('rain').textContent          = `${rain} mm`;     // ✅
    document.getElementById('visibility').textContent    = vis >= 1000
      ? `${(vis/1000).toFixed(1)} km` : `${vis} m`;                          // ✅

    const uvI = uvInfo(uv);
    document.getElementById('uv-index').textContent = uvI.label;             // ✅ string interna
    document.getElementById('uv-tip').textContent   = uvI.tip;               // ✅
    document.getElementById('uv-item').classList.toggle('uv-alert', uvI.alert);

    // --- Previsão horária ---
    const hourlyScroll = document.getElementById('hourly-scroll');
    hourlyScroll.innerHTML = ''; // Limpa o container — dados são inseridos com textContent
    const curH   = sanitizeApiString(c.time, '').slice(11,13);
    const hTimes = data.hourly?.time  ?? [];
    const hTemps = data.hourly?.temperature_2m ?? [];
    const hCodes = data.hourly?.weather_code   ?? [];
    let count = 0;

    for (let i = 0; i < hTimes.length && count < 12; i++) {
      const h = sanitizeApiString(hTimes[i], '').slice(11,13);
      if (h < curH) continue;
      const isNow  = h === curH;
      const hInfo  = getWmo(hCodes[i]);
      const hTemp  = Math.round(sanitizeNumber(hTemps[i], 20, -80, 60));

      // ✅ Cria elementos e usa textContent — nunca innerHTML com dados da API
      const item     = document.createElement('div');
      item.className = `hourly-item${isNow ? ' now' : ''}`;

      const spanTime = document.createElement('span');
      spanTime.className   = 'hourly-time';
      spanTime.textContent = isNow ? 'Agora' : formatHour(hTimes[i]);   // ✅

      const spanIcon = document.createElement('span');
      spanIcon.className   = 'hourly-icon';
      spanIcon.textContent = hInfo.icon;                                  // ✅ emoji constante

      const spanTemp = document.createElement('span');
      spanTemp.className   = 'hourly-temp';
      spanTemp.textContent = `${hTemp}°`;                                 // ✅ número sanitizado

      item.appendChild(spanTime);
      item.appendChild(spanIcon);
      item.appendChild(spanTemp);
      hourlyScroll.appendChild(item);
      count++;
    }

    // --- Previsão 7 dias ---
    const weeklyGrid = document.getElementById('weekly-grid');
    weeklyGrid.innerHTML = '';
    const DAYS   = ['domingo','segunda','terça','quarta','quinta','sexta','sábado'];
    const dTimes = data.daily?.time                ?? [];
    const dCodes = data.daily?.weather_code        ?? [];
    const dMax   = data.daily?.temperature_2m_max  ?? [];
    const dMin   = data.daily?.temperature_2m_min  ?? [];

    dTimes.forEach((dateStr, idx) => {
      const safeDateStr = sanitizeApiString(dateStr, '');
      let dayName;
      try {
        const d   = new Date(safeDateStr + 'T12:00:00');
        dayName   = idx === 0 ? 'Hoje' : toTitle(DAYS[d.getDay()]);
      } catch { dayName = '—'; }

      const dInfo    = getWmo(dCodes[idx]);
      const dMaxTemp = Math.round(sanitizeNumber(dMax[idx], 20, -80, 60));
      const dMinTemp = Math.round(sanitizeNumber(dMin[idx], 10, -80, 60));

      // ✅ createElement + textContent — nunca innerHTML com dados da API
      const item = document.createElement('div');
      item.className = `weekly-item${idx === 0 ? ' today' : ''}`;

      const spanDay = document.createElement('span');
      spanDay.className   = 'weekly-day';
      spanDay.textContent = dayName;                // ✅

      const spanIcon = document.createElement('span');
      spanIcon.className   = 'weekly-icon';
      spanIcon.textContent = dInfo.icon;            // ✅ emoji constante

      const divTemps = document.createElement('div');
      divTemps.className = 'weekly-temps';

      const spanMax = document.createElement('span');
      spanMax.className   = 'weekly-max';
      spanMax.textContent = `${dMaxTemp}°`;         // ✅ número sanitizado

      const spanMin = document.createElement('span');
      spanMin.className   = 'weekly-min';
      spanMin.textContent = `/ ${dMinTemp}°`;       // ✅

      divTemps.appendChild(spanMax);
      divTemps.appendChild(spanMin);
      item.appendChild(spanDay);
      item.appendChild(spanIcon);
      item.appendChild(divTemps);
      weeklyGrid.appendChild(item);
    });

    // Salvar cache e histórico
    saveCache(geo, data);
    if (!fromCache) saveHistory(geo.name);

    // Exibir card
    weatherCard.classList.remove('hidden');
    if (!silent) weatherCard.scrollIntoView({ behavior:'smooth', block:'nearest' });
  };

  if (!silent && !weatherCard.classList.contains('hidden')) {
    animateCardOut(doRender);
  } else {
    doRender();
  }
}

// ============================================================
//  FETCH PRINCIPAL
// ============================================================
async function fetchWeather(rawCity, { silent = false } = {}) {
  // 1. Sanitiza o input
  const city = sanitizeInput(rawCity);
  if (!city) {
    showError(new AppError('invalid_input', ''));
    return;
  }

  // 2. Rate limiting
  if (!RateLimit.canCall()) {
    showError(new AppError('rate_limit', `Aguarde ${RateLimit.msUntilNext()}s antes de buscar novamente.`));
    return;
  }

  showLoading(silent);

  try {
    const geo  = await getCoordinates(city);
    const data = await getWeather(geo.latitude, geo.longitude);
    currentGeo = geo;
    hideLoading(silent);
    renderWeather(geo, data, { silent });
    scheduleAutoRefresh(geo.name);

  } catch (err) {
    hideLoading(silent);

    if (!silent) {
      // Tenta mostrar cache como fallback offline
      const cache = loadCache();
      if (cache && err instanceof AppError && err.type === 'network') {
        renderWeather(cache.geo, cache.data, { fromCache: true });
      } else {
        showError(err);
      }
    }
    // Se silent, falha silenciosamente — mantém dados visíveis
    if (silent) console.warn('[SolOuChuva] Atualização silenciosa falhou:', err.message);
  }
}

// ============================================================
//  AUTO-REFRESH SILENCIOSO (10 min)
// ============================================================
function scheduleAutoRefresh(city) {
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(() => {
    fetchWeather(city, { silent: true });
  }, REFRESH_MS);
}

// ============================================================
//  GEOLOCALIZAÇÃO
// ============================================================
geoBtn.addEventListener('click', () => {
  if (!navigator.geolocation) {
    showError(new AppError('geo', 'Geolocalização não suportada neste navegador.'));
    return;
  }

  geoBtn.disabled     = true;
  geoBtn.textContent  = '📍 Detectando localização…'; // ✅ textContent
  showLoading(false);

  navigator.geolocation.getCurrentPosition(
    async pos => {
      try {
        const { latitude, longitude } = pos.coords;

        // Sanitiza coordenadas vindas do browser
        const safeLat = sanitizeNumber(latitude,  0, -90,  90);
        const safeLon = sanitizeNumber(longitude, 0, -180, 180);

        // Reverse geocoding via Nominatim (OpenStreetMap)
        const locData = await safeFetch(
          `https://nominatim.openstreetmap.org/reverse?lat=${safeLat}&lon=${safeLon}&format=json&accept-language=pt`
        );

        // ✅ Sanitiza tudo que vem da API externa de geocoding
        const addr  = locData?.address ?? {};
        const city  = sanitizeApiString(
          addr.city || addr.town || addr.village || addr.county,
          'Minha localização'
        );

        cityInput.value = city; // ✅ value — não innerHTML

        const data = await getWeather(safeLat, safeLon);
        const geo  = {
          name:      city,
          admin1:    sanitizeApiString(addr.state,   ''),
          country:   sanitizeApiString(addr.country, ''),
          latitude:  safeLat,
          longitude: safeLon,
        };
        currentGeo = geo;
        hideLoading(false);
        renderWeather(geo, data);
        scheduleAutoRefresh(city);

      } catch (err) {
        showError(err instanceof AppError ? err : new AppError('geo', 'Não foi possível obter o clima da sua localização.'));
      } finally {
        geoBtn.disabled    = false;
        geoBtn.textContent = '📍 Usar minha localização atual'; // ✅
      }
    },
    err => {
      hideLoading(false);
      geoBtn.disabled    = false;
      geoBtn.textContent = '📍 Usar minha localização atual'; // ✅
      const msg = err.code === 1
        ? 'Permissão negada. Busque manualmente ou habilite a localização.'
        : 'Não foi possível detectar sua localização. Tente novamente.';
      showError(new AppError('geo', msg));
    },
    { timeout: 10000, maximumAge: 60000 }
  );
});

// ============================================================
//  COMPARTILHAR
// ============================================================
shareBtn.addEventListener('click', async () => {
  // ✅ Lê textContent dos elementos — seguro, é o que está na tela
  const city  = document.getElementById('city-name').textContent;
  const temp  = document.getElementById('temp-value').textContent;
  const desc  = document.getElementById('weather-desc').textContent;
  const icon  = document.getElementById('weather-icon').textContent;
  const look  = document.getElementById('look-msg').textContent;
  const humor = document.getElementById('humor-msg').textContent;

  // Sanitiza antes de montar o texto (nunca confiar cegamente em textContent de inputs externos)
  const shareText = [
    `${icon} Clima em ${sanitizeApiString(city)}: ${sanitizeNumber(Number(temp),0,-80,60)}°C — ${sanitizeApiString(desc)}`,
    `👕 Look do dia: ${sanitizeApiString(look)}`,
    sanitizeApiString(humor),
    '\n📱 via SolOuChuva?',
  ].join('\n');

  if (navigator.share) {
    try {
      await navigator.share({ title: `SolOuChuva? — ${sanitizeApiString(city)}`, text: shareText });
    } catch (e) {
      // Usuário cancelou — não é um erro
    }
  } else {
    try {
      await navigator.clipboard.writeText(shareText);
      shareBtn.textContent = '✅ Copiado para a área de transferência!'; // ✅
      setTimeout(() => { shareBtn.textContent = '📤 Compartilhar clima'; }, 2500);
    } catch {
      shareBtn.textContent = '😕 Não foi possível compartilhar';
      setTimeout(() => { shareBtn.textContent = '📤 Compartilhar clima'; }, 2500);
    }
  }
});


// ============================================================
//  💨 ROSA DOS VENTOS — renderWindCard
// ============================================================

/** Converte graus em nome de direção */
function degToCardinal(deg) {
  const dirs = ['Norte','NNL','Nordeste','NNE','Leste','ENE','Sudeste','ESE',
                'Sul','SSE','Sudoeste','OSO','Oeste','ONO','Noroeste','NNO'];
  return dirs[Math.round(deg / 22.5) % 16];
}

/** Escala Beaufort simplificada */
function beaufortLabel(kmh) {
  if (kmh < 2)   return '🍃 Calmaria';
  if (kmh < 12)  return '🌿 Brisa leve';
  if (kmh < 20)  return '🍃 Brisa suave';
  if (kmh < 29)  return '💨 Brisa moderada';
  if (kmh < 39)  return '🌬️ Brisa forte';
  if (kmh < 50)  return '🌬️ Vento fresco';
  if (kmh < 62)  return '💨 Vento forte';
  if (kmh < 75)  return '🌀 Ventania';
  if (kmh < 89)  return '⚠️ Tempestade';
  if (kmh < 103) return '⛈️ Tempestade forte';
  return                '🚨 Furacão';
}

function renderWindCard(speedKmh, dirDeg) {
  // Atualiza o card lateral
  const speedBig  = document.getElementById('wind-speed-big');
  const dirText   = document.getElementById('wind-direction-text');
  const bftText   = document.getElementById('wind-beaufort-text');
  const needle    = document.getElementById('compass-needle');
  const barFill   = document.getElementById('wind-bar-fill');

  if (!speedBig) return;

  // Velocidade
  speedBig.textContent = '';
  const numSpan = document.createElement('span');
  numSpan.style.cssText = 'font-size:inherit;color:inherit;font-weight:inherit;';
  numSpan.textContent = speedKmh;
  const unitSpan = document.createElement('span');
  unitSpan.textContent = ' km/h';
  speedBig.appendChild(numSpan);
  speedBig.appendChild(unitSpan);

  // Direção e Beaufort
  dirText.textContent = `↗ De ${degToCardinal(dirDeg)} (${dirDeg}°)`;
  bftText.textContent = beaufortLabel(speedKmh);

  // Rotaciona a seta: a seta aponta para ONDE o vento vai
  // A direção meteorológica indica de onde VEM, então +180°
  const needleAngle = (dirDeg + 180) % 360;
  needle.style.transform = `translateX(-50%) translateY(-100%) rotate(${needleAngle}deg)`;

  // Barra de intensidade (0–120 km/h = 0–100%)
  const pct = Math.min(100, Math.round((speedKmh / 120) * 100));
  barFill.style.width = `${pct}%`;
}

// ============================================================
//  🌧️ EFEITOS VISUAIS CLIMÁTICOS — Canvas de Partículas
// ============================================================

const FX = (() => {
  const canvas  = document.getElementById('weather-canvas');
  const ctx     = canvas ? canvas.getContext('2d') : null;
  let particles = [];
  let animId    = null;
  let mode      = 'none'; // 'rain' | 'snow' | 'none'

  function resize() {
    if (!canvas) return;
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
  }

  // Goticulas de chuva
  function makeRaindrop() {
    return {
      x:       Math.random() * canvas.width,
      y:       Math.random() * canvas.height * -1,
      len:     Math.random() * 18 + 8,
      speed:   Math.random() * 10 + 10,
      opacity: Math.random() * 0.4 + 0.15,
      width:   Math.random() * 1.2 + 0.4,
    };
  }

  // Flocos de neve
  function makeSnowflake() {
    return {
      x:       Math.random() * canvas.width,
      y:       Math.random() * canvas.height * -1,
      r:       Math.random() * 3 + 1.5,
      speed:   Math.random() * 1.5 + 0.5,
      drift:   (Math.random() - 0.5) * 0.6,
      opacity: Math.random() * 0.5 + 0.3,
      angle:   Math.random() * Math.PI * 2,
      spin:    (Math.random() - 0.5) * 0.04,
    };
  }

  function initParticles(count) {
    particles = [];
    for (let i = 0; i < count; i++) {
      if (mode === 'rain') {
        const p = makeRaindrop();
        p.y = Math.random() * canvas.height; // espalha verticalmente no início
        particles.push(p);
      } else if (mode === 'snow') {
        const p = makeSnowflake();
        p.y = Math.random() * canvas.height;
        particles.push(p);
      }
    }
  }

  function drawRain() {
    particles.forEach((p, i) => {
      ctx.save();
      ctx.globalAlpha = p.opacity;
      ctx.strokeStyle = '#a8d8ff';
      ctx.lineWidth   = p.width;
      ctx.lineCap     = 'round';
      ctx.beginPath();
      ctx.moveTo(p.x, p.y);
      ctx.lineTo(p.x - 2, p.y + p.len);
      ctx.stroke();
      ctx.restore();

      p.y += p.speed;
      p.x -= 1.5;
      if (p.y > canvas.height + p.len) {
        particles[i] = makeRaindrop();
      }
    });
  }

  function drawSnow() {
    particles.forEach((p, i) => {
      ctx.save();
      ctx.globalAlpha = p.opacity;
      ctx.fillStyle   = '#e8f4ff';
      ctx.shadowColor = '#ffffff';
      ctx.shadowBlur  = 4;
      // Desenha um hexágono simplificado (floco)
      ctx.beginPath();
      for (let a = 0; a < 6; a++) {
        const angle = p.angle + (a * Math.PI / 3);
        const x = p.x + p.r * Math.cos(angle);
        const y = p.y + p.r * Math.sin(angle);
        a === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
      }
      ctx.closePath();
      ctx.fill();
      ctx.restore();

      p.y     += p.speed;
      p.x     += p.drift + Math.sin(p.y / 60) * 0.3;
      p.angle += p.spin;
      if (p.y > canvas.height + p.r * 2) {
        particles[i] = makeSnowflake();
      }
    });
  }

  function loop() {
    if (!ctx) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    if (mode === 'rain')  drawRain();
    if (mode === 'snow')  drawSnow();
    animId = requestAnimationFrame(loop);
  }

  function stop() {
    if (animId) cancelAnimationFrame(animId);
    animId = null;
    if (ctx) ctx.clearRect(0, 0, canvas.width, canvas.height);
    particles = [];
  }

  function start(newMode, count) {
    stop();
    mode = newMode;
    resize();
    initParticles(count);
    loop();
  }

  // API pública
  return { start, stop, resize };
})();

window.addEventListener('resize', () => FX.resize(), { passive: true });

/** Ativa o efeito correto com base no código WMO e temperatura */
function triggerWeatherFX(code, temp) {
  const sunGlow = document.getElementById('sun-glow');

  // — NEVE: códigos de neve/granizo OU temperatura ≤ 2°C e qualquer precipitação
  const isSnow = [71,73,75,77,85,86].includes(code) || (temp <= 2 && [51,53,55,61,63,65,80,81,82].includes(code));

  // — CHUVA: códigos de chuva/garoa/tempestade (e não neve)
  const isRain = !isSnow && [51,53,55,61,63,65,80,81,82,95,96,99].includes(code);

  // — SOL: quente ou escaldante E céu limpo/pouco nublado
  const isSunny = (temp >= 26) && [0,1,2].includes(code);

  // Efeitos de partículas
  if (isSnow) {
    FX.start('snow', 80);
  } else if (isRain) {
    // Intensidade da chuva varia com o código
    const drops = [51,53,55].includes(code) ? 60 : [80,81].includes(code) ? 110 : 160;
    FX.start('rain', drops);
  } else {
    FX.stop();
  }

  // Efeito de sol
  if (sunGlow) {
    sunGlow.classList.toggle('active', isSunny);
  }
}


// ============================================================
//  ☔ PREVISÃO DE CHUVA (próximas 24h)
// ============================================================
function renderRainForecast(data) {
  const container = document.getElementById('rain-forecast');
  if (!container) return;

  container.innerHTML = '';

  const hTimes = data.hourly?.time ?? [];
  const hProb  = data.hourly?.precipitation_probability ?? [];
  const hCodes = data.hourly?.weather_code ?? [];

  const curTime = data.current?.time ?? '';
  const curH    = curTime.slice(11, 13);
  let count     = 0;

  for (let i = 0; i < hTimes.length && count < 8; i++) {
    const h = hTimes[i].slice(11, 13);
    if (h < curH && count === 0) continue;

    const prob    = sanitizeNumber(hProb[i], 0, 0, 100);
    const hCode   = sanitizeNumber(hCodes[i], 0, 0, 99);
    const isRainy = prob >= 50;

    const col = document.createElement('div');
    col.className = `rain-col${isRainy ? ' rainy' : ''}`;

    // Hora
    const spanH = document.createElement('span');
    spanH.className   = 'rain-hour';
    spanH.textContent = count === 0 ? 'Agora' : hTimes[i].slice(11, 16);

    // Barra de probabilidade (vertical, de baixo para cima)
    const barWrap = document.createElement('div');
    barWrap.className = 'rain-bar-wrap';
    const bar = document.createElement('div');
    bar.className = 'rain-bar';
    bar.style.height = `${prob}%`;
    bar.style.background = prob >= 70
      ? '#4fc3f7'
      : prob >= 40
        ? '#81d4fa'
        : 'rgba(255,255,255,.2)';
    barWrap.appendChild(bar);

    // Percentual
    const spanP = document.createElement('span');
    spanP.className   = 'rain-pct';
    spanP.textContent = `${prob}%`;

    // Ícone do tempo nessa hora
    const spanI = document.createElement('span');
    spanI.className   = 'rain-icon';
    spanI.textContent = getWmo(hCode).icon;

    col.appendChild(spanH);
    col.appendChild(barWrap);
    col.appendChild(spanP);
    col.appendChild(spanI);
    container.appendChild(col);
    count++;
  }
}

// ============================================================
//  📈 GRÁFICO DE TEMPERATURA — SVG inline, 24h
// ============================================================
function renderTempChart(data) {
  const svg = document.getElementById('temp-chart-svg');
  if (!svg) return;

  const hTimes = data.hourly?.time ?? [];
  const hTemps = data.hourly?.temperature_2m ?? [];
  const curTime = data.current?.time ?? '';
  const curH    = curTime.slice(11, 13);

  // Coleta as próximas 24 horas a partir da hora atual
  let points = [];
  for (let i = 0; i < hTimes.length && points.length < 24; i++) {
    const h = hTimes[i].slice(11, 13);
    if (h < curH && points.length === 0) continue;
    points.push({
      hour: hTimes[i].slice(11, 16),
      temp: Math.round(sanitizeNumber(hTemps[i], 20, -80, 60)),
    });
  }
  if (points.length < 2) return;

  const W   = 320;
  const H   = 90;
  const PAD = { top: 16, bot: 20, left: 8, right: 8 };
  const innerW = W - PAD.left - PAD.right;
  const innerH = H - PAD.top  - PAD.bot;

  const temps = points.map(p => p.temp);
  const tMin  = Math.min(...temps) - 2;
  const tMax  = Math.max(...temps) + 2;
  const tRange = tMax - tMin || 1;

  const toX = idx => PAD.left + (idx / (points.length - 1)) * innerW;
  const toY = t   => PAD.top  + innerH - ((t - tMin) / tRange) * innerH;

  // Monta path da linha
  const pathD = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${toX(i).toFixed(1)},${toY(p.temp).toFixed(1)}`).join(' ');

  // Monta path da área (fecha para baixo)
  const areaD = pathD
    + ` L${toX(points.length - 1).toFixed(1)},${H - PAD.bot} L${toX(0).toFixed(1)},${H - PAD.bot} Z`;

  // Limpa SVG anterior
  while (svg.firstChild) svg.removeChild(svg.firstChild);

  const ns = 'http://www.w3.org/2000/svg';

  // Defs: gradiente da área
  const defs = document.createElementNS(ns, 'defs');
  const grad = document.createElementNS(ns, 'linearGradient');
  grad.setAttribute('id', 'tgrad');
  grad.setAttribute('x1', '0'); grad.setAttribute('y1', '0');
  grad.setAttribute('x2', '0'); grad.setAttribute('y2', '1');
  const stop1 = document.createElementNS(ns, 'stop');
  stop1.setAttribute('offset', '0%');   stop1.setAttribute('stop-color', '#00d4ff'); stop1.setAttribute('stop-opacity', '0.4');
  const stop2 = document.createElementNS(ns, 'stop');
  stop2.setAttribute('offset', '100%'); stop2.setAttribute('stop-color', '#00d4ff'); stop2.setAttribute('stop-opacity', '0.02');
  grad.appendChild(stop1); grad.appendChild(stop2);
  defs.appendChild(grad);
  svg.appendChild(defs);

  // Área preenchida
  const area = document.createElementNS(ns, 'path');
  area.setAttribute('d', areaD);
  area.setAttribute('fill', 'url(#tgrad)');
  svg.appendChild(area);

  // Linha principal
  const line = document.createElementNS(ns, 'path');
  line.setAttribute('d', pathD);
  line.setAttribute('fill', 'none');
  line.setAttribute('stroke', '#00d4ff');
  line.setAttribute('stroke-width', '2');
  line.setAttribute('stroke-linecap', 'round');
  line.setAttribute('stroke-linejoin', 'round');
  // Animação de desenho
  const len = line.getTotalLength ? line.getTotalLength() : 500;
  line.setAttribute('stroke-dasharray', len);
  line.setAttribute('stroke-dashoffset', len);
  line.style.animation = 'chart-draw 1.4s ease forwards';
  svg.appendChild(line);

  // Labels (hora + temp) a cada 4 pontos para não poluir
  points.forEach((p, i) => {
    if (i % 4 !== 0 && i !== points.length - 1) return;
    const x = toX(i);
    const y = toY(p.temp);

    // Ponto
    const dot = document.createElementNS(ns, 'circle');
    dot.setAttribute('cx', x.toFixed(1));
    dot.setAttribute('cy', y.toFixed(1));
    dot.setAttribute('r', '3');
    dot.setAttribute('fill', '#00d4ff');
    dot.setAttribute('stroke', '#fff');
    dot.setAttribute('stroke-width', '1');
    svg.appendChild(dot);

    // Temperatura
    const tLabel = document.createElementNS(ns, 'text');
    tLabel.setAttribute('x', x.toFixed(1));
    tLabel.setAttribute('y', (y - 6).toFixed(1));
    tLabel.setAttribute('text-anchor', 'middle');
    tLabel.setAttribute('font-size', '9');
    tLabel.setAttribute('font-weight', '700');
    tLabel.setAttribute('fill', '#fff');
    tLabel.setAttribute('font-family', 'Nunito, sans-serif');
    tLabel.textContent = `${p.temp}°`;
    svg.appendChild(tLabel);

    // Hora (embaixo)
    const hLabel = document.createElementNS(ns, 'text');
    hLabel.setAttribute('x', x.toFixed(1));
    hLabel.setAttribute('y', (H - PAD.bot + 12).toFixed(1));
    hLabel.setAttribute('text-anchor', 'middle');
    hLabel.setAttribute('font-size', '8');
    hLabel.setAttribute('fill', 'rgba(255,255,255,0.5)');
    hLabel.setAttribute('font-family', 'Nunito, sans-serif');
    hLabel.textContent = i === 0 ? 'Agora' : p.hour;
    svg.appendChild(hLabel);
  });

  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
}

// ============================================================
//  🌅 ANIMAÇÃO DE NASCER / PÔR DO SOL
// ============================================================
function renderSunArc(sunriseISO, sunsetISO, nowISO) {
  const arc    = document.getElementById('sun-arc');
  const sunDot = document.getElementById('sun-dot');
  const srEl   = document.getElementById('sunrise-time');
  const ssEl   = document.getElementById('sunset-time');
  if (!arc || !sunDot || !srEl || !ssEl) return;

  // Extrai HH:MM
  const toMin = iso => {
    const t = String(iso ?? '').slice(11, 16);
    if (!/^\d{2}:\d{2}$/.test(t)) return null;
    const [h, m] = t.split(':').map(Number);
    return h * 60 + m;
  };

  const srMin  = toMin(sunriseISO);
  const ssMin  = toMin(sunsetISO);
  const now    = new Date();
  const nowMin = now.getHours() * 60 + now.getMinutes();

  if (srMin === null || ssMin === null) return;

  const srStr = String(sunriseISO ?? '').slice(11, 16);
  const ssStr = String(sunsetISO  ?? '').slice(11, 16);
  srEl.textContent = `🌅 ${srStr}`;
  ssEl.textContent = `🌇 ${ssStr}`;

  // Progresso: 0 = nascer, 1 = pôr
  const total    = ssMin - srMin;
  const elapsed  = nowMin - srMin;
  const progress = Math.max(0, Math.min(1, total > 0 ? elapsed / total : 0));

  // Arco semi-circular: 180° de 180° a 0° (percorre da esquerda para direita)
  const W = 280, H = 100, CX = 140, CY = 100, R = 90;
  const angle = Math.PI - progress * Math.PI; // de 180° → 0°
  const sx = CX + R * Math.cos(angle);
  const sy = CY - R * Math.sin(angle);

  // Caminho completo do arco
  arc.setAttribute('d', `M ${CX - R} ${CY} A ${R} ${R} 0 0 1 ${CX + R} ${CY}`);

  // Posiciona o sol no arco
  sunDot.setAttribute('cx', sx.toFixed(1));
  sunDot.setAttribute('cy', sy.toFixed(1));

  // Cor do sol: dourado durante o dia, laranja no nascer/pôr
  const isGoldenHour = progress < 0.12 || progress > 0.88;
  sunDot.setAttribute('fill', isGoldenHour ? '#ff8f00' : '#ffe566');

  // Trilha percorrida (arco já feito)
  const trailAngleEnd = angle;
  const trailX = CX + R * Math.cos(trailAngleEnd);
  const trailY = CY - R * Math.sin(trailAngleEnd);
  const trail = document.getElementById('sun-trail');
  if (trail && progress > 0) {
    trail.setAttribute('d', `M ${CX - R} ${CY} A ${R} ${R} 0 0 1 ${trailX.toFixed(1)} ${trailY.toFixed(1)}`);
    trail.style.opacity = '1';
  } else if (trail) {
    trail.style.opacity = '0';
  }
}

// ============================================================
//  🔔 NOTIFICAÇÕES DE MUDANÇA BRUSCA (Web Notifications API)
// ============================================================
const WeatherAlert = (() => {
  let lastCode = null;
  let lastTemp = null;
  let lastWind = null;
  let permission = Notification?.permission ?? 'default';

  async function requestPerm() {
    if (!('Notification' in window)) return false;
    if (permission === 'granted') return true;
    if (permission === 'denied')  return false;
    const result = await Notification.requestPermission();
    permission = result;
    return result === 'granted';
  }

  function notify(title, body, icon = '🌦️') {
    if (permission !== 'granted') return;
    try {
      new Notification(title, {
        body,
        icon:   'https://cdn.jsdelivr.net/gh/twitter/twemoji@14/assets/72x72/1f326.png',
        badge:  'https://cdn.jsdelivr.net/gh/twitter/twemoji@14/assets/72x72/1f326.png',
        tag:    'sol-ou-chuva-alert',
        silent: false,
      });
    } catch {}
  }

  // Grupos de código WMO para comparação
  const GROUP = code => {
    if ([0,1,2,3].includes(code))           return 'claro';
    if ([45,48].includes(code))             return 'neblina';
    if ([51,53,55,61,63,65,80,81].includes(code)) return 'chuva';
    if ([82,95,96,99].includes(code))       return 'tempestade';
    if ([71,73,75,77,85,86].includes(code)) return 'neve';
    return 'outro';
  };

  function check(code, temp, wind) {
    const grp = GROUP(code);

    // Primeira leitura: só registra, não notifica
    if (lastCode === null) {
      lastCode = code; lastTemp = temp; lastWind = wind;
      return;
    }

    const lastGrp = GROUP(lastCode);
    const alerts  = [];

    // Mudança de grupo climático
    if (grp !== lastGrp) {
      const MSGS = {
        tempestade: ['⛈️ Tempestade chegando!', 'O clima piorou muito. Busque abrigo!'],
        chuva:      ['🌧️ Chuva a caminho!',     'Leve um guarda-chuva ao sair.'],
        neve:       ['❄️ Nevando agora!',        'Cuidado com as pistas escorregadias!'],
        neblina:    ['🌫️ Neblina formando',      'Reduza a velocidade se for dirigir.'],
        claro:      ['☀️ Tempo melhorando!',     'O céu está abrindo. Aproveite!'],
      };
      const m = MSGS[grp];
      if (m) alerts.push({ title: m[0], body: m[1] });
    }

    // Queda brusca de temperatura (≥6°C)
    if (lastTemp - temp >= 6) {
      alerts.push({ title: '🥶 Temperatura caiu muito!', body: `De ${lastTemp}°C para ${temp}°C. Vista uma blusa!` });
    }
    // Alta brusca de temperatura (≥6°C)
    if (temp - lastTemp >= 6) {
      alerts.push({ title: '🔥 Temperatura subiu muito!', body: `De ${lastTemp}°C para ${temp}°C. Hidrate-se!` });
    }

    // Vento forte súbito (passou de 40 km/h)
    if (lastWind < 40 && wind >= 40) {
      alerts.push({ title: '💨 Ventos fortes!', body: `Vento a ${wind} km/h. Cuidado com objetos soltos!` });
    }

    alerts.forEach(a => notify(a.title, a.body));

    lastCode = code; lastTemp = temp; lastWind = wind;
  }

  return { requestPerm, check };
})();

function checkWeatherAlert(code, temp, wind) {
  WeatherAlert.check(code, temp, wind);
}

// ============================================================
//  🔍 AUTOCOMPLETE + VALIDAÇÃO VISUAL DE INPUT
//
//  Fluxo:
//  1. Usuário digita → debounce 400ms → valida formato
//  2. Se válido (≥2 chars) → busca sugestões na API de geocoding
//  3. Mostra dropdown com até 6 cidades + bandeira + região
//  4. Navegação por teclado (↑↓ Enter Esc) e toque/clique
//  5. Validação visual inline: borda colorida + ícone + hint text
//  6. Rate limit próprio para o autocomplete (600ms entre calls)
// ============================================================

// ---------- Referências DOM do autocomplete ----------
const searchBox       = document.getElementById('search-box');
const inputStatus     = document.getElementById('input-status');
const inputHint       = document.getElementById('input-hint');
const autocompleteList = document.getElementById('autocomplete-list');

// ---------- Estado do autocomplete ----------
let acDebounce   = null;
let acLastCall   = 0;
let acIndex      = -1;   // índice do item selecionado pelo teclado
let acResults    = [];   // resultados atuais
let acOpen       = false;
const AC_RATE_MS = 600;  // mínimo entre chamadas ao geocoding para autocomplete
const AC_DEBOUNCE_MS = 400;
const AC_MAX_RESULTS = 6;

// ---------- Ícones de países (emoji flags via código ISO) ----------
function countryFlag(countryCode) {
  if (!countryCode || countryCode.length !== 2) return '🌍';
  // Converte código ISO (ex: "BR") em emoji de bandeira
  const offset = 0x1F1E6 - 65;
  return String.fromCodePoint(
    countryCode.toUpperCase().charCodeAt(0) + offset,
    countryCode.toUpperCase().charCodeAt(1) + offset
  );
}

// ---------- Define estado visual da caixa de busca ----------
// state: '' | 'valid' | 'invalid' | 'loading'
// hint: { text, type: 'ok'|'error'|'warn'|'info' }
function setInputState(state, hint = null) {
  searchBox.classList.remove('input-valid', 'input-invalid', 'input-loading');
  if (state) searchBox.classList.add(`input-${state}`);

  // Ícone inline
  const icons = { valid: '✅', invalid: '❌', loading: '' };
  inputStatus.textContent = icons[state] ?? '';

  // Hint text
  if (hint && hint.text) {
    inputHint.textContent = hint.text;   // ✅ textContent
    inputHint.className   = `input-hint visible hint-${hint.type ?? 'info'}`;
  } else {
    inputHint.textContent = '';
    inputHint.className   = 'input-hint';
  }
}

// ---------- Abre/fecha o dropdown ----------
function openAutocomplete() {
  acOpen = true;
  autocompleteList.classList.remove('hidden');
  cityInput.setAttribute('aria-expanded', 'true');
}
function closeAutocomplete() {
  acOpen = false;
  acIndex = -1;
  autocompleteList.classList.add('hidden');
  autocompleteList.innerHTML = '';
  cityInput.setAttribute('aria-expanded', 'false');
}

// ---------- Mostra spinner dentro do dropdown ----------
function showAcLoading() {
  openAutocomplete();
  autocompleteList.innerHTML = '';
  const li = document.createElement('li');
  li.className = 'autocomplete-loading';
  const spinner = document.createElement('span');
  spinner.className = 'autocomplete-spinner';
  const txt = document.createElement('span');
  txt.textContent = 'Buscando cidades…';   // ✅ textContent
  li.appendChild(spinner);
  li.appendChild(txt);
  autocompleteList.appendChild(li);
}

// ---------- Renderiza lista de sugestões ----------
function renderAutocomplete(results) {
  autocompleteList.innerHTML = '';
  acResults = results;
  acIndex   = -1;

  if (!results.length) {
    openAutocomplete();
    const li = document.createElement('li');
    li.className   = 'autocomplete-empty';
    li.textContent = '😕 Nenhuma cidade encontrada. Tente outro nome.'; // ✅ textContent
    autocompleteList.appendChild(li);
    return;
  }

  openAutocomplete();
  results.forEach((r, idx) => {
    const li   = document.createElement('li');
    li.setAttribute('role', 'option');
    li.setAttribute('aria-selected', 'false');
    li.className = 'autocomplete-item';
    li.tabIndex  = -1;

    // Bandeira
    const flag = document.createElement('span');
    flag.className   = 'autocomplete-flag';
    flag.textContent = countryFlag(r.country_code);  // ✅ textContent, valor interno

    // Texto (cidade + região)
    const textDiv = document.createElement('div');
    textDiv.className = 'autocomplete-text';

    const citySpan = document.createElement('span');
    citySpan.className   = 'autocomplete-city';
    citySpan.textContent = sanitizeApiString(r.name);  // ✅ sanitizado

    const regionSpan = document.createElement('span');
    regionSpan.className   = 'autocomplete-region';
    // Monta: "São Paulo, SP • Brasil"
    const parts = [r.admin1, r.admin2, r.country].filter(Boolean).map(s => sanitizeApiString(s));
    regionSpan.textContent = parts.join(' • ');  // ✅ textContent

    textDiv.appendChild(citySpan);
    textDiv.appendChild(regionSpan);
    li.appendChild(flag);
    li.appendChild(textDiv);

    // Clique ou toque → seleciona
    li.addEventListener('mousedown', e => {
      e.preventDefault(); // evita perda de foco do input antes do clique processar
      selectSuggestion(idx);
    });
    li.addEventListener('touchend', e => {
      e.preventDefault();
      selectSuggestion(idx);
    });

    autocompleteList.appendChild(li);
  });
}

// ---------- Seleciona uma sugestão ----------
function selectSuggestion(idx) {
  const r = acResults[idx];
  if (!r) return;
  const name = sanitizeApiString(r.name);
  cityInput.value = name;  // ✅ .value
  closeAutocomplete();
  setInputState('valid', { text: `✅ ${name} selecionada`, type: 'ok' });
  fetchWeather(name);
}

// ---------- Destaca o item ativo no teclado ----------
function highlightAcItem(newIndex) {
  const items = autocompleteList.querySelectorAll('.autocomplete-item');
  if (!items.length) return;

  // Remove destaque anterior
  items.forEach(el => {
    el.classList.remove('active');
    el.setAttribute('aria-selected', 'false');
  });

  // Wrapping: ↑ no primeiro vai para o último, ↓ no último vai para o primeiro
  if (newIndex < 0)           newIndex = items.length - 1;
  if (newIndex >= items.length) newIndex = 0;

  acIndex = newIndex;
  items[acIndex].classList.add('active');
  items[acIndex].setAttribute('aria-selected', 'true');
  items[acIndex].scrollIntoView({ block: 'nearest' });
  cityInput.setAttribute('aria-activedescendant', items[acIndex].id || '');
}

// ---------- Busca sugestões na API de geocoding ----------
async function fetchSuggestions(query) {
  // Rate limit próprio para autocomplete
  const now = Date.now();
  if (now - acLastCall < AC_RATE_MS) return;
  acLastCall = now;

  showAcLoading();

  try {
    const url  = `https://geocoding-api.open-meteo.com/v1/search?name=${encodeURIComponent(query)}&count=${AC_MAX_RESULTS}&language=pt&format=json`;
    const data = await safeFetch(url, 5000); // timeout menor para autocomplete (5s)

    if (!Array.isArray(data?.results) || data.results.length === 0) {
      renderAutocomplete([]);
      return;
    }

    renderAutocomplete(data.results);
  } catch {
    // Falha silenciosa no autocomplete — não mostra erro para não atrapalhar o usuário
    closeAutocomplete();
  }
}

// ---------- Valida e reage ao que o usuário digita ----------
function handleInputChange(val) {
  const trimmed = val.trim();

  // Vazio
  if (trimmed.length === 0) {
    setInputState('', null);
    closeAutocomplete();
    return;
  }

  // Muito curto
  if (trimmed.length < 2) {
    setInputState('invalid', { text: 'Digite pelo menos 2 letras', type: 'error' });
    closeAutocomplete();
    return;
  }

  // Muito longo
  if (trimmed.length > 100) {
    setInputState('invalid', { text: 'Nome muito longo (máx. 100 caracteres)', type: 'error' });
    closeAutocomplete();
    return;
  }

  // Caracteres inválidos
  const safePattern = /^[\p{L}\s,.\-']+$/u;
  if (!safePattern.test(trimmed)) {
    setInputState('invalid', { text: 'Use apenas letras, espaços e hífens', type: 'error' });
    closeAutocomplete();
    return;
  }

  // Válido → inicia busca de sugestões
  setInputState('loading', { text: 'Buscando sugestões…', type: 'info' });
  fetchSuggestions(trimmed);
}

// ---------- Event: input com debounce ----------
cityInput.addEventListener('input', () => {
  clearTimeout(acDebounce);
  clearTimeout(debounceTimer);

  const val = cityInput.value;

  // Reação imediata para feedback de estado (sem debounce)
  const trimmed = val.trim();
  if (trimmed.length === 0) {
    setInputState('', null);
    closeAutocomplete();
    return;
  }

  // Debounce para a chamada de API
  acDebounce = setTimeout(() => handleInputChange(val), AC_DEBOUNCE_MS);
});

// ---------- Event: teclado (↑↓ Enter Esc Tab) ----------
cityInput.addEventListener('keydown', e => {
  if (acOpen && acResults.length) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      highlightAcItem(acIndex + 1);
      return;
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      highlightAcItem(acIndex - 1);
      return;
    }
    if (e.key === 'Enter' && acIndex >= 0) {
      e.preventDefault();
      selectSuggestion(acIndex);
      return;
    }
    if (e.key === 'Escape' || e.key === 'Tab') {
      closeAutocomplete();
      return;
    }
  }

  if (e.key === 'Enter') {
    clearTimeout(acDebounce);
    clearTimeout(debounceTimer);
    closeAutocomplete();
    cityInput.blur();
    fetchWeather(cityInput.value);
  }
});

// ---------- Fecha ao clicar fora ----------
document.addEventListener('click', e => {
  if (!e.target.closest('.search-wrapper')) {
    closeAutocomplete();
  }
});

// ---------- Botão buscar ----------
searchBtn.addEventListener('click', () => {
  clearTimeout(acDebounce);
  clearTimeout(debounceTimer);
  closeAutocomplete();
  fetchWeather(cityInput.value);
});

// ============================================================
//  INIT
// ============================================================
initAccordions();
renderHistory();

window.addEventListener('load', () => {
  const cache = loadCache();
  if (cache) {
    renderWeather(cache.geo, cache.data, { fromCache: true });
  }
  cityInput.value = 'Barueri'; // ✅ .value
  fetchWeather('Barueri');

  // Botão de notificações
  const notifBtn = document.getElementById('notif-btn');
  if ('Notification' in window && notifBtn) {
    notifBtn.classList.remove('hidden');
    if (Notification.permission === 'granted') {
      notifBtn.textContent   = '🔔 Alertas ativados!';
      notifBtn.classList.add('granted');
    }
    notifBtn.addEventListener('click', async () => {
      const ok = await WeatherAlert.requestPerm();
      if (ok) {
        notifBtn.textContent = '🔔 Alertas ativados!';
        notifBtn.classList.add('granted');
      } else {
        notifBtn.textContent = '🔕 Permissão negada';
      }
    });
  }
});
