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
    permissions: ['activeTab', 'storage'],
    host_permissions: [`${new URL(backendUrl).origin}/*`],
    // Chỉ xin khi activeTab không đủ để tải PDF (người dùng bấm nút cấp quyền).
    optional_host_permissions: ['<all_urls>'],
    action: { default_title: 'Ký số PDF này với KysoQR' },
    content_security_policy: {
      extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'",
    },
  },
});
