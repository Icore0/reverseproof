// electron-builder afterPack hook. `npm i -D @electron/fuses`, then in package.json:
//   "build": { "afterPack": "templates/electron/flip-fuses.js" }
// Runs BEFORE code signing, which is required (flipping a fuse changes the binary).
const path = require('node:path');
const { flipFuses, FuseVersion, FuseV1Options } = require('@electron/fuses');

exports.default = async function afterPack(context) {
  const name = context.packager.appInfo.productFilename;
  const target =
    context.electronPlatformName === 'darwin' ? path.join(context.appOutDir, `${name}.app`)
    : context.electronPlatformName === 'win32' ? path.join(context.appOutDir, `${name}.exe`)
    : path.join(context.appOutDir, name);

  await flipFuses(target, {
    version: FuseVersion.V1,
    [FuseV1Options.RunAsNode]: false,                          // no ELECTRON_RUN_AS_NODE shell
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false, // no NODE_OPTIONS injection
    [FuseV1Options.EnableNodeCliInspectArguments]: false,      // no --inspect / --inspect-brk
    [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true, // detect a swapped app.asar
    [FuseV1Options.OnlyLoadAppFromAsar]: true,                 // no loose app/ override folder
    [FuseV1Options.EnableCookieEncryption]: true,
    [FuseV1Options.GrantFileProtocolExtraPrivileges]: false,   // set true only if you load file:// UI
  });
};
// Verify afterwards:  npx reverseproof scan "dist/mac-arm64/YourApp.app"
