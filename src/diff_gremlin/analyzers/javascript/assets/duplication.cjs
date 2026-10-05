/* Native jscpd APIs: fixed windows, explicit source inventory, no target configuration. */
const fs = require('node:fs');
const path = require('node:path');
const [corePath, tokenizerPath, finderPath, requestPath, outputFlag, outputPath] = process.argv.slice(2);
const core = require(corePath);
const {Tokenizer, getSupportedFormats} = require(tokenizerPath);
const {getFilesToDetect, InFilesDetector, JsonReporter} = require(finderPath);
const limits = {minLines: 5, minTokens: 50, maxLines: 1000, maxSize: '100kb'};

function optionsFor(files, formats) {
  return {...core.getDefaultOptions(), ...limits, path: files,
    format: formats, absolute: true, noSymlinks: true,
    cache: false, ignore: [], gitignore: false, skipLocal: false, ignoreCase: false,
    ignorePattern: [], formatsExts: {}, formatsNames: {}, reporters: [],
    silent: true, debug: false, verbose: false};
}

async function observe(request) {
  const options = optionsFor(request.files, request.formats);
  const entries = getFilesToDetect(options);
  const detectorFiles = entries.map(entry => entry.path);
  const statistic = new core.Statistic();
  const store = new core.MemoryStore();
  try {
    const detector = new InFilesDetector(new Tokenizer(), store, statistic, options);
    const clones = await detector.detect(entries);
    const native = new JsonReporter(options).generateJson(clones, statistic.getStatistic());
    return {...native, invocation: request.invocation, options: limits,
      requested_files: request.files, requested_formats: request.formats, detector_files: detectorFiles,
      tokenizer_formats: getSupportedFormats()};
  } finally {
    store.close();
  }
}

async function main() {
  if (outputFlag !== '--output') throw new Error('Invalid controlled output argument');
  const request = JSON.parse(fs.readFileSync(requestPath, 'utf8'));
  const report = await observe(request);
  fs.mkdirSync(outputPath, {recursive: true});
  fs.writeFileSync(path.join(outputPath, 'jscpd-report.json'), JSON.stringify(report));
}

main().catch(() => {console.error('Controlled jscpd evidence collection failed'); process.exitCode = 2;});
