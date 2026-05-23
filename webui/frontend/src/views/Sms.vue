<template>
  <div class="sms-root">
    <header class="wizard-header">
      <div class="brand">
        <span class="brand-prompt">$</span>
        <span class="brand-name">gpt-pay</span>
        <span class="brand-sub">// SMS 接码</span>
      </div>
      <div class="run-nav">
        <RouterLink to="/wizard" class="nav-link">配置向导</RouterLink>
        <RouterLink to="/run" class="nav-link">运行</RouterLink>
        <RouterLink to="/sms" class="nav-link active">SMS 接码</RouterLink>
        <button class="header-btn" @click="logout">退出</button>
      </div>
    </header>

    <main class="sms-body">
      <section class="sms-card">
        <div class="term-divider" data-tail="──────────">pvapins 平台配置</div>
        <p class="sms-hint">
          pvapins 注册页目前对服务器抓取返回 Cloudflare 403，所以这里先做通用 API 适配。
          你给我 pvapins 的 API 文档/API Key 后，我再把“取号/查码/释放”按钮接成固定接口。
        </p>
        <div class="form-grid">
          <label>Base URL<input v-model="form.base_url" placeholder="https://pvapins.com" /></label>
          <label>API Key<input v-model="form.api_key" type="password" placeholder="可选" /></label>
          <label>Token<input v-model="form.token" type="password" placeholder="可选" /></label>
          <label>Service<input v-model="form.service" placeholder="openai" /></label>
          <label>Country<input v-model="form.country" placeholder="例如 US / JP / ID" /></label>
          <label>Operator<input v-model="form.operator" placeholder="可选" /></label>
        </div>
        <div class="actions">
          <button @click="loadConfig" :disabled="busy">刷新配置</button>
          <button @click="saveConfig" :disabled="busy">保存配置</button>
        </div>
      </section>

      <section class="sms-card">
        <div class="term-divider" data-tail="──────────">通用接口调试</div>
        <p class="sms-hint">临时用于验证 pvapins API：填 path/参数后调用，返回原始 JSON/文本。</p>
        <div class="form-grid">
          <label>Method
            <select v-model="generic.method"><option>GET</option><option>POST</option></select>
          </label>
          <label>Path<input v-model="generic.path" placeholder="/api/..." /></label>
        </div>
        <label class="wide">Params JSON<textarea v-model="generic.params" rows="5" placeholder='{"service":"openai"}' /></label>
        <label class="wide">Body JSON<textarea v-model="generic.json_body" rows="5" placeholder='{}' /></label>
        <div class="actions"><button @click="callGeneric" :disabled="busy">调用接口</button></div>
        <pre class="sms-result">{{ resultText }}</pre>
      </section>
    </main>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from "vue";
import { RouterLink, useRouter } from "vue-router";
import { useMessage } from "naive-ui";
import { api } from "../api/client";

const router = useRouter();
const message = useMessage();
const busy = ref(false);
const form = ref({ base_url: "https://pvapins.com", api_key: "", token: "", service: "openai", country: "", operator: "", extra: {} as Record<string, any> });
const generic = ref({ method: "GET", path: "", params: "{}", json_body: "{}" });
const resultText = ref("等待调用…");

async function logout() {
  await api.post("/logout").catch(() => {});
  router.push("/login");
}
function parseJson(s: string) {
  try { return JSON.parse(s || "{}"); } catch { throw new Error("JSON 格式错误"); }
}
async function loadConfig() {
  busy.value = true;
  try {
    const r = await api.get("/sms/config");
    form.value = { ...form.value, ...(r.data.config || {}) };
    message.success("已加载 SMS 配置");
  } catch (e: any) { message.error(e?.response?.data?.detail || "加载失败"); }
  finally { busy.value = false; }
}
async function saveConfig() {
  busy.value = true;
  try {
    await api.post("/sms/config", form.value);
    message.success("SMS 配置已保存");
  } catch (e: any) { message.error(e?.response?.data?.detail || "保存失败"); }
  finally { busy.value = false; }
}
async function callGeneric() {
  busy.value = true;
  try {
    const r = await api.post("/sms/generic", {
      method: generic.value.method,
      path: generic.value.path,
      params: parseJson(generic.value.params),
      json_body: parseJson(generic.value.json_body),
    });
    resultText.value = JSON.stringify(r.data, null, 2);
  } catch (e: any) { resultText.value = e?.response?.data?.detail || e?.message || String(e); }
  finally { busy.value = false; }
}

onMounted(loadConfig);
</script>

<style scoped>
.sms-root { min-height: 100vh; background: #faf8f3; color: #1c1a15; font-family: JetBrains Mono, ui-monospace, monospace; }
.wizard-header { display:flex; justify-content:space-between; align-items:center; padding:14px 18px; border-bottom:1px solid #d4cdb9; background:#fff; }
.brand { display:flex; gap:8px; align-items:center; }
.brand-prompt { color:#b25e1f; font-weight:700; }
.brand-name { font-weight:800; }
.brand-sub { color:#7a7363; }
.run-nav { display:flex; gap:10px; align-items:center; }
.nav-link,.header-btn { border:1px solid #d4cdb9; background:#fff; padding:7px 10px; color:#1c1a15; text-decoration:none; cursor:pointer; }
.nav-link.active { background:#1c1a15; color:#fff; }
.sms-body { display:grid; grid-template-columns:minmax(360px, 520px) 1fr; gap:18px; padding:18px; }
.sms-card { background:#fff; border:1px solid #d4cdb9; padding:16px; }
.term-divider { color:#7a7363; margin-bottom:12px; }
.sms-hint { color:#7a7363; line-height:1.6; }
.form-grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
label { display:flex; flex-direction:column; gap:6px; font-size:12px; color:#3a362e; }
input,select,textarea { border:1px solid #d4cdb9; padding:8px; font-family:inherit; background:#fff; color:#1c1a15; }
.wide { margin-top:12px; }
.actions { display:flex; gap:10px; margin-top:14px; }
button { border:1px solid #1c1a15; background:#1c1a15; color:#fff; padding:8px 12px; cursor:pointer; }
button:disabled { opacity:.5; cursor:not-allowed; }
.sms-result { margin-top:12px; padding:12px; background:#1c1a15; color:#f8f1df; overflow:auto; max-height:460px; white-space:pre-wrap; }
@media (max-width: 980px) { .sms-body { grid-template-columns:1fr; } .form-grid { grid-template-columns:1fr; } }
</style>
