import commonjs from '@rollup/plugin-commonjs';
import resolve from '@rollup/plugin-node-resolve';
import builtins from 'rollup-plugin-node-builtins';
import globals from 'rollup-plugin-node-globals';
import json from '@rollup/plugin-json';

export default {
  input: 'src/util.js',
  external: ['@peculiar/webcrypto'],
  output: {
    format: 'cjs',
    name: 'app',
    file: 'build/bundle.js',
    compact: true
  },
  plugins: [
    json(),
    globals(),
    builtins(),
    resolve({
      browser: true
    }),
    commonjs({
      include: 'node_modules/**'
    })
  ]
}
