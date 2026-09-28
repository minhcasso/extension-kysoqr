import { Component, type ReactNode } from 'react';

/** Không để lỗi hiển thị làm trắng/đen cả trang: hiện lỗi và cho tải lại. */
export class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error) {
    console.error('KysoQR viewer crashed', error);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="center-card">
        <h2>Đã có lỗi xảy ra</h2>
        <div className="error">{this.state.error.message}</div>
        <p className="muted small">
          Yêu cầu ký đã gửi (nếu có) vẫn được lưu trong “Yêu cầu ký gần đây”.
        </p>
        <button type="button" className="primary" onClick={() => location.reload()}>
          Tải lại trang
        </button>
      </div>
    );
  }
}
