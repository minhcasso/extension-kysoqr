import { describe, expect, it } from 'vitest';
import { describeShape, findString } from './cas-client';

describe('findString', () => {
  it('tìm được field ở cấp gốc hoặc bị bọc trong object con', () => {
    expect(findString({ qrContent: 'a' }, 'qrContent')).toBe('a');
    expect(findString({ requestId: 'r', data: { signRequest: { qrContent: 'b' } } }, 'qrContent')).toBe('b');
    expect(findString({ data: {} }, 'qrContent')).toBeUndefined();
  });
});

describe('describeShape', () => {
  it('chỉ giữ tên field và kiểu, không giữ giá trị', () => {
    expect(describeShape({ a: 'secret', b: { c: 1, d: null }, e: [{ f: true }] })).toEqual({
      a: 'string',
      b: { c: 'number', d: 'null' },
      e: [{ f: 'boolean' }],
    });
  });
});
