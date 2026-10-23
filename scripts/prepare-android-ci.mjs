import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const rootDir = process.cwd();
const androidDir = path.join(rootDir, 'android');
const templateArchive = path.join(
  rootDir,
  'node_modules',
  '@capacitor',
  'cli',
  'assets',
  'android-template.tar.gz'
);
const cordovaArchive = path.join(
  rootDir,
  'node_modules',
  '@capacitor',
  'cli',
  'assets',
  'capacitor-cordova-android-plugins.tar.gz'
);

const ZIP_MAGIC = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function hasValidMagic(filePath, magic) {
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile() || stat.size < magic.length) return false;
    const fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(magic.length);
    fs.readSync(fd, buf, 0, magic.length, 0);
    fs.closeSync(fd);
    return buf.equals(magic);
  } catch {
    return false;
  }
}

function collectFilesByExt(dir, ext, results = []) {
  if (!fs.existsSync(dir)) return results;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      collectFilesByExt(full, ext, results);
    } else if (entry.name.endsWith(ext)) {
      results.push(full);
    }
  }
  return results;
}

function ensureAndroidBinaries() {
  if (!fs.existsSync(androidDir) || !fs.existsSync(templateArchive)) {
    return;
  }

  const wrapperJar = path.join(androidDir, 'gradle', 'wrapper', 'gradle-wrapper.jar');
  const resDir = path.join(androidDir, 'app', 'src', 'main', 'res');
  const existingPngs = collectFilesByExt(resDir, '.png');

  const wrapperValid = hasValidMagic(wrapperJar, ZIP_MAGIC);
  const pngsValid =
    existingPngs.length >= 15 && existingPngs.every((png) => hasValidMagic(png, PNG_MAGIC));

  if (!wrapperValid || !pngsValid) {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-cap-tpl-'));
    try {
      execFileSync('tar', ['-xzf', templateArchive, '-C', tmpDir]);

      const tplWrapper = path.join(tmpDir, 'gradle', 'wrapper', 'gradle-wrapper.jar');
      if (fs.existsSync(tplWrapper) && !wrapperValid) {
        fs.mkdirSync(path.dirname(wrapperJar), { recursive: true });
        fs.copyFileSync(tplWrapper, wrapperJar);
        console.log('[prepare-android-ci] Restored clean gradle-wrapper.jar from Capacitor template');
      }

      const tplResDir = path.join(tmpDir, 'app', 'src', 'main', 'res');
      const tplPngs = collectFilesByExt(tplResDir, '.png');
      let restoredPngCount = 0;
      for (const srcPng of tplPngs) {
        const rel = path.relative(tplResDir, srcPng);
        const destPng = path.join(resDir, rel);
        if (!hasValidMagic(destPng, PNG_MAGIC)) {
          fs.mkdirSync(path.dirname(destPng), { recursive: true });
          fs.copyFileSync(srcPng, destPng);
          restoredPngCount += 1;
        }
      }
      if (restoredPngCount > 0) {
        console.log(`[prepare-android-ci] Restored ${restoredPngCount} binary PNG resource(s)`);
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  const cordovaPluginsDir = path.join(androidDir, 'capacitor-cordova-android-plugins');
  if (!fs.existsSync(path.join(cordovaPluginsDir, 'build.gradle')) && fs.existsSync(cordovaArchive)) {
    fs.mkdirSync(cordovaPluginsDir, { recursive: true });
    execFileSync('tar', ['-xzf', cordovaArchive, '-C', cordovaPluginsDir]);
    console.log('[prepare-android-ci] Initialized capacitor-cordova-android-plugins directory');
  }

  const gradlewPath = path.join(androidDir, 'gradlew');
  if (fs.existsSync(gradlewPath)) {
    const content = fs.readFileSync(gradlewPath, 'utf8').replace(/\r\n/g, '\n');
    fs.writeFileSync(gradlewPath, content, { mode: 0o755 });
    fs.chmodSync(gradlewPath, 0o755);
  }
}

ensureAndroidBinaries();
