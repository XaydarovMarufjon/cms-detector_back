import * as fs from 'fs';
import * as path from 'path';

jest.mock('fs', () => ({ existsSync: jest.fn(), readFileSync: jest.fn() }));

describe('startup environment loader', () => {
  const key = 'ENV_LOADER_TEST_VALUE';
  const secondKey = 'ENV_LOADER_TEST_OTHER';
  let originalEnv: NodeJS.ProcessEnv;
  const exists = jest.mocked(fs.existsSync);
  const read = jest.mocked(fs.readFileSync);

  function load(content: string) {
    read.mockReturnValue(content);
    jest.isolateModules(() => {
      jest.requireActual('./env-loader');
    });
  }

  beforeEach(() => {
    originalEnv = process.env;
    // An isolated synthetic environment prevents reading, changing or logging secrets.
    process.env = {};
    exists.mockReset().mockReturnValue(true);
    read.mockReset();
  });

  afterEach(() => {
    process.env = originalEnv;
    jest.restoreAllMocks();
  });

  it('loads only .env from the startup working directory as UTF-8', () => {
    const cwd = path.resolve('synthetic-config-directory');
    jest.spyOn(process, 'cwd').mockReturnValue(cwd);
    load(`${key}=loaded`);
    expect(exists).toHaveBeenCalledTimes(1);
    expect(exists).toHaveBeenCalledWith(path.join(cwd, '.env'));
    expect(read).toHaveBeenCalledTimes(1);
    expect(read).toHaveBeenCalledWith(path.join(cwd, '.env'), 'utf8');
    expect(process.env).toEqual({ [key]: 'loaded' });
  });

  it('does not read or change the environment when the file is absent', () => {
    exists.mockReturnValue(false);
    process.env[secondKey] = 'existing';
    load(`${key}=not-loaded`);
    expect(read).not.toHaveBeenCalled();
    expect(process.env).toEqual({ [secondKey]: 'existing' });
  });

  it.each(['existing', '', '0', 'false'])(
    'preserves existing environment value %j over the file',
    (value) => {
      process.env[key] = value;
      load(`${key}=replacement\n${secondKey}=new`);
      expect(process.env).toEqual({ [key]: value, [secondKey]: 'new' });
    },
  );

  it.each(['\n', '\r\n'])(
    'supports line separator %j and skips blank/comment lines',
    (separator) => {
      load(
        [
          '\uFEFF  ',
          ' # ignored=value',
          '',
          `${key}=one`,
          `${secondKey}=two`,
        ].join(separator),
      );
      expect(process.env).toEqual({ [key]: 'one', [secondKey]: 'two' });
    },
  );

  it.each([
    ['plain', '  plain  ', 'plain'],
    ['empty', '   ', ''],
    ['double quotes', '"  a=b # c  "', '  a=b # c  '],
    ['single quotes', "'  a=b # c  '", '  a=b # c  '],
    ['empty quotes', '""', ''],
    ['embedded equals', 'one=two=three', 'one=two=three'],
    ['unmatched quotes', '"one', '"one'],
    ['mismatched quotes', '"one\'', '"one\''],
    [
      'literal interpolation',
      '${ENV_LOADER_TEST_OTHER}',
      '${ENV_LOADER_TEST_OTHER}',
    ],
    ['literal escapes', '"one\\ntwo"', 'one\\ntwo'],
    ['literal inline comment', 'one # two', 'one # two'],
    ['unicode', 'Қиймат — qiymat', 'Қиймат — qiymat'],
  ])('preserves the current %s value contract', (_label, input, expected) => {
    load(`  ${key}  = ${input} `);
    expect(process.env).toEqual({ [key]: expected });
  });

  it('uses the first value for duplicate keys, including an empty first value', () => {
    load(
      `${key}=first\n${key}=second\n${secondKey}=\n${secondKey}=replacement`,
    );
    expect(process.env).toEqual({ [key]: 'first', [secondKey]: '' });
  });

  it('accepts underscore, letter and digit names without changing case', () => {
    load('_START=one\nlower_2=two\nLOWER_2=three');
    expect(process.env).toEqual({
      _START: 'one',
      lower_2: 'two',
      LOWER_2: 'three',
    });
  });

  it('ignores unsupported key syntax and malformed lines without losing later entries', () => {
    load(
      [
        '=missing',
        'NO_SEPARATOR',
        '1DIGIT=bad',
        'WITH-DASH=bad',
        'WITH.DOT=bad',
        'WITH SPACE=bad',
        'export EXPORTED=bad',
        'ÜNICODE=bad',
        `${key}=valid`,
      ].join('\n'),
    );
    expect(process.env).toEqual({ [key]: 'valid' });
  });

  it('propagates a read failure without partially changing environment', () => {
    const failure = new Error('synthetic read failure');
    process.env[key] = 'existing';
    read.mockImplementation(() => {
      throw failure;
    });
    expect(() =>
      jest.isolateModules(() => {
        jest.requireActual('./env-loader');
      }),
    ).toThrow(failure);
    expect(process.env).toEqual({ [key]: 'existing' });
  });

  it('propagates an existence-check failure without reading', () => {
    const failure = new Error('synthetic stat failure');
    exists.mockImplementation(() => {
      throw failure;
    });
    expect(() => load(`${key}=unused`)).toThrow(failure);
    expect(read).not.toHaveBeenCalled();
    expect(process.env).toEqual({});
  });
});
