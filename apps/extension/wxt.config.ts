import { defineConfig } from 'wxt';

const backendUrl = process.env.WXT_BACKEND_URL ?? 'http://localhost:8787';

export default defineConfig({
  modules: ['@wxt-dev/module-react'],
  // Thư mục không bắt đầu bằng dấu chấm để thấy được trong hộp thoại "Load unpacked" trên macOS.
  outDir: 'dist',
  outDirTemplate: '{{browser}}',
  manifest: {
    name: 'KysoQR – Ký số PDF',
    description: 'Ký số file PDF ngay trên Chrome bằng Cas ID',
    // webRequest: chỉ để nhận ra PDF (Content-Type); chỉ hoạt động khi người dùng cấp quyền mọi trang web.
    permissions: ['activeTab', 'storage', 'webRequest'],
    host_permissions: [`${new URL(backendUrl).origin}/*`],
    // Xin khi người dùng bật "Tự mở PDF bằng KysoQR" hoặc khi activeTab không đủ để tải PDF.
    optional_host_permissions: ['<all_urls>'],
    action: { default_title: 'Ký số PDF này với KysoQR' },
    content_security_policy: {
      extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'",
    },
  },
});
