// Passive technology fingerprinting: looks only at the homepage response
// (headers, cookies, HTML) that the header check already fetched. No extra
// requests are made to the target.

const CATEGORY_ORDER = [
  'Web server',
  'CDN / hosting',
  'CMS / platform',
  'Frontend framework',
  'JavaScript libraries',
  'Language / runtime',
  'Analytics / marketing',
  'Security / payments',
];

// header: [name, regex|null]  body: regex  cookie: regex
const SIGNATURES = [
  // Web servers
  { name: 'nginx', category: 'Web server', header: ['server', /nginx/i] },
  { name: 'Apache HTTP Server', category: 'Web server', header: ['server', /apache/i] },
  { name: 'Microsoft IIS', category: 'Web server', header: ['server', /microsoft-iis/i] },
  { name: 'LiteSpeed', category: 'Web server', header: ['server', /litespeed/i] },
  { name: 'OpenResty', category: 'Web server', header: ['server', /openresty/i] },
  { name: 'Caddy', category: 'Web server', header: ['server', /caddy/i] },
  { name: 'gunicorn', category: 'Web server', header: ['server', /gunicorn/i] },
  { name: 'Envoy', category: 'Web server', header: ['server', /envoy/i] },
  { name: 'Google Web Server', category: 'Web server', header: ['server', /^gws$/i] },

  // CDN / hosting vendors
  { name: 'Cloudflare', category: 'CDN / hosting', header: ['cf-ray', null] },
  { name: 'Cloudflare', category: 'CDN / hosting', header: ['server', /cloudflare/i] },
  { name: 'Amazon CloudFront', category: 'CDN / hosting', header: ['x-amz-cf-id', null] },
  { name: 'Amazon S3', category: 'CDN / hosting', header: ['server', /amazons3/i] },
  { name: 'AWS (ELB)', category: 'CDN / hosting', cookie: /^(AWSALB|AWSELB)/i },
  { name: 'Fastly', category: 'CDN / hosting', header: ['x-fastly-request-id', null] },
  { name: 'Fastly', category: 'CDN / hosting', header: ['via', /varnish/i], also: ['x-served-by', /cache-/i] },
  { name: 'Akamai', category: 'CDN / hosting', header: ['x-akamai-transformed', null] },
  { name: 'Akamai', category: 'CDN / hosting', header: ['server', /akamai/i] },
  { name: 'Vercel', category: 'CDN / hosting', header: ['x-vercel-id', null] },
  { name: 'Netlify', category: 'CDN / hosting', header: ['x-nf-request-id', null] },
  { name: 'Netlify', category: 'CDN / hosting', header: ['server', /netlify/i] },
  { name: 'GitHub Pages', category: 'CDN / hosting', header: ['x-github-request-id', null] },
  { name: 'Fly.io', category: 'CDN / hosting', header: ['fly-request-id', null] },
  { name: 'Azure Front Door', category: 'CDN / hosting', header: ['x-azure-ref', null] },
  { name: 'Google Cloud', category: 'CDN / hosting', header: ['x-cloud-trace-context', null] },
  { name: 'Heroku', category: 'CDN / hosting', header: ['via', /vegur/i] },
  { name: 'Sucuri', category: 'CDN / hosting', header: ['x-sucuri-id', null] },
  { name: 'Imperva', category: 'CDN / hosting', header: ['x-iinfo', null] },

  // CMS / platforms
  { name: 'WordPress', category: 'CMS / platform', body: /\/wp-content\/|\/wp-includes\//i },
  { name: 'WordPress', category: 'CMS / platform', body: /<meta[^>]+name=["']generator["'][^>]+content=["']WordPress/i },
  { name: 'Drupal', category: 'CMS / platform', header: ['x-drupal-cache', null] },
  { name: 'Drupal', category: 'CMS / platform', body: /<meta[^>]+name=["']generator["'][^>]+content=["']Drupal/i },
  { name: 'Joomla', category: 'CMS / platform', body: /<meta[^>]+name=["']generator["'][^>]+content=["']Joomla/i },
  { name: 'Shopify', category: 'CMS / platform', header: ['x-shopid', null] },
  { name: 'Shopify', category: 'CMS / platform', body: /cdn\.shopify\.com/i },
  { name: 'Wix', category: 'CMS / platform', header: ['x-wix-request-id', null] },
  { name: 'Squarespace', category: 'CMS / platform', body: /static\.squarespace\.com|squarespace-cdn/i },
  { name: 'Webflow', category: 'CMS / platform', body: /<html[^>]+data-wf-(page|site)/i },
  { name: 'Ghost', category: 'CMS / platform', body: /<meta[^>]+name=["']generator["'][^>]+content=["']Ghost/i },
  { name: 'Magento', category: 'CMS / platform', cookie: /^mage-/i },

  // Frontend frameworks
  { name: 'Next.js', category: 'Frontend framework', body: /\/_next\/static\//i },
  { name: 'Next.js', category: 'Frontend framework', header: ['x-powered-by', /next\.js/i] },
  { name: 'Nuxt', category: 'Frontend framework', body: /__NUXT__|\/_nuxt\//i },
  { name: 'React', category: 'Frontend framework', body: /data-reactroot|react(\.production|-dom)/i },
  { name: 'Vue.js', category: 'Frontend framework', body: /vue(\.runtime)?(\.min)?\.js|data-v-[0-9a-f]{6,}/i },
  { name: 'Angular', category: 'Frontend framework', body: /\sng-version=|ng-app/i },
  { name: 'Svelte / SvelteKit', category: 'Frontend framework', body: /\/_app\/immutable\/|svelte-[a-z0-9]{5,}/i },
  { name: 'Astro', category: 'Frontend framework', body: /\/_astro\/|astro-island/i },
  { name: 'Gatsby', category: 'Frontend framework', body: /___gatsby|\/page-data\//i },

  // JS / CSS libraries
  { name: 'jQuery', category: 'JavaScript libraries', body: /jquery[-.\d]*(\.min)?\.js/i },
  { name: 'Bootstrap', category: 'JavaScript libraries', body: /bootstrap[-.\d]*(\.min)?\.(css|js)/i },
  { name: 'Tailwind CSS', category: 'JavaScript libraries', body: /tailwind(css)?[-.\d]*(\.min)?\.css|cdn\.tailwindcss\.com/i },
  { name: 'Font Awesome', category: 'JavaScript libraries', body: /font-?awesome/i },

  // Languages / runtimes
  { name: 'PHP', category: 'Language / runtime', header: ['x-powered-by', /php/i] },
  { name: 'PHP', category: 'Language / runtime', cookie: /^PHPSESSID$/i },
  { name: 'ASP.NET', category: 'Language / runtime', header: ['x-powered-by', /asp\.net/i] },
  { name: 'ASP.NET', category: 'Language / runtime', header: ['x-aspnet-version', null] },
  { name: 'Express (Node.js)', category: 'Language / runtime', header: ['x-powered-by', /express/i] },
  { name: 'Java (JSP / servlet)', category: 'Language / runtime', cookie: /^JSESSIONID$/i },
  { name: 'Ruby on Rails', category: 'Language / runtime', header: ['x-runtime', /^\d/] , also: ['x-request-id', null] },
  { name: 'Django', category: 'Language / runtime', cookie: /^csrftoken$/i },
  { name: 'Laravel', category: 'Language / runtime', cookie: /^laravel_session$/i },

  // Analytics / marketing
  { name: 'Google Analytics', category: 'Analytics / marketing', body: /google-analytics\.com\/(analytics|ga)\.js|gtag\/js\?id=G-|gtag\/js\?id=UA-/i },
  { name: 'Google Tag Manager', category: 'Analytics / marketing', body: /googletagmanager\.com\/gtm\.js/i },
  { name: 'Meta Pixel', category: 'Analytics / marketing', body: /connect\.facebook\.net\/[^"']+\/fbevents\.js/i },
  { name: 'Hotjar', category: 'Analytics / marketing', body: /static\.hotjar\.com/i },
  { name: 'Cloudflare Web Analytics', category: 'Analytics / marketing', body: /static\.cloudflareinsights\.com/i },
  { name: 'Plausible', category: 'Analytics / marketing', body: /plausible\.io\/js/i },
  { name: 'HubSpot', category: 'Analytics / marketing', body: /js\.hs-scripts\.com|js\.hsforms\.net/i },

  // Security / payments
  { name: 'Google reCAPTCHA', category: 'Security / payments', body: /google\.com\/recaptcha\//i },
  { name: 'hCaptcha', category: 'Security / payments', body: /hcaptcha\.com\/1\/api\.js/i },
  { name: 'Stripe', category: 'Security / payments', body: /js\.stripe\.com/i },
  { name: 'PayPal', category: 'Security / payments', body: /paypal(objects)?\.com\/(sdk|js)/i },
];

function cookieNames(setCookies) {
  return setCookies.map((c) => c.split('=')[0].trim());
}

function matches(sig, home, cookies) {
  const test = (pair) => {
    const value = home.headers.get(pair[0]);
    return value !== null && (pair[1] === null || pair[1].test(value));
  };
  if (sig.header && !test(sig.header)) return false;
  if (sig.also && !test(sig.also)) return false;
  if (sig.body && !sig.body.test(home.body)) return false;
  if (sig.cookie && !cookies.some((name) => sig.cookie.test(name))) return false;
  return Boolean(sig.header || sig.body || sig.cookie);
}

function detectTech(home) {
  const name = 'Technology Stack';
  if (!home.ok) {
    return { name, status: 'info', message: `Could not read the homepage to fingerprint it: ${home.error}`, details: {} };
  }

  const cookies = cookieNames(home.setCookies);
  const byCategory = new Map();
  SIGNATURES.forEach((sig) => {
    if (!matches(sig, home, cookies)) return;
    if (!byCategory.has(sig.category)) byCategory.set(sig.category, new Set());
    byCategory.get(sig.category).add(sig.name);
  });

  const details = {};
  let total = 0;
  CATEGORY_ORDER.forEach((category) => {
    if (!byCategory.has(category)) return;
    const names = [...byCategory.get(category)];
    total += names.length;
    details[category] = names;
  });

  const server = home.headers.get('server');
  const poweredBy = home.headers.get('x-powered-by');
  if (server) details['Server banner'] = server;
  if (poweredBy) details['X-Powered-By banner'] = poweredBy;
  const generator = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']{1,80})["']/i.exec(home.body);
  if (generator) details['Generator tag'] = generator[1];

  const message = total === 0
    ? 'No well-known technologies fingerprinted from the homepage'
    : `${total} technolog${total === 1 ? 'y' : 'ies'} detected from response headers, cookies and page source`;
  details.note = 'Passive detection from the homepage response only; results are best-effort and can miss or misattribute technologies.';
  return { name, status: 'info', message, details };
}

module.exports = { detectTech };
