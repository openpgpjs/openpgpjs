'use strict';

var openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

var chai = require('chai'),
	expect = chai.expect;

describe('Key', function() {
  var twoKeys =
       ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
        'Version: GnuPG v2.0.19 (GNU/Linux)',
        '',
        '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',
        'PepQmgsu',
        '=w6wd',
        '-----END PGP PUBLIC KEY BLOCK-----'].join("\n");

  var pub_revoked =
      ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
      'Version: GnuPG v2.0.19 (GNU/Linux)',
      '',
      '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',
      'pMiJM+NJAQ==',
      '=ok+o',
      '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

  var pub_v3 =
      ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
      'Version: SKS 1.1.3',
      '',
      'mQENAy9J/w4AAAEIALBDDD4vWqG/Jg59ghhMYAa+E7ECCTv2At8hxsM5cMP8P9sMLjs+GMfD',
      'IdQSOqlQXbunYADvM1l/h2fOuUMoYFIIGaUsO5Daxvd9uWceM4DVzhXMeJZb9wc5jEJEF21+',
      'qidKj5OGsMyTrg++mn4Gh/aFXvvy3N3KWaQpPfNi3NRZUpNLz0IlfbXVBQGD6reLoxPptJun',
      'NqpClyRiesgq8HCscmB2oQo+b9KzSSgzU9qQJA4SljMYVmJ2sDE/sjREI8iKL8lIgUMhJG9q',
      'NggWjuxFTpVcGKkuQFJIvdL+UhTVvEBuqw6n4cmFAzfZ/AInJM032qLtsaIf5begFKI3up0A',
      'BRGJARUDBSAxm7HC5begFKI3up0BAbdDB/0TOcI0ec+OPxC5RTZAltgIgyUc0yOjHoTD/yBh',
      'WjZdQ9YVrLGMWTW4fjhm4rFnppVZKS/N71bwI76SnN9zO4pPfx86aQPR7StmSLJxB+cfh2GL',
      'gudJoG9ifhJWdNYMUD/yhA0TpJkdHMD5yTDE5Ce/PqKLviiX9C5MPW0AT1MDvafQlzeUXfb5',
      '1a71vQNPw7W1NBAVZRwztm7TNUaxWMFuOmUtOJpq4F/qDQTIHW2zGPJvl47rpf6JSiyIyU70',
      'l0deiQcZOXPC80tgInhNoBrz3zbEXhXRJo1fHkr2YSLclpJaoUOHsPxoyrNB28ASL5ZknPwI',
      'Zx3+cFxaGpRprfSdtCFKb2huIEEuIFBlcnJ5IDxwZXJyeUBwaG9lbml4Lm5ldD6JARUDBRAv',
      'Sf8k5begFKI3up0BAcbGB/0eLod2qrQxoE2/RUWQtqklOPUj/p/ZTmvZm8BgsdIflb0AMeey',
      '9o8AbxyAgA3pcrcCjcye79M1Ma2trEvRksvs8hViuq3BXXjDbjPZi3wTtKSvbAC022OV52Sb',
      '8/sgiTGp7xC8QMqS8w4ZeKoxJGh1TVMYrevUA8a2Rr5aDqrR3EA4rifSHwkVjJWOPF69xiKt',
      'IVA0LcYJvGsPOQCf2ag+nOcnDrF4dvcmg6XZ/RyLepve+1qkhXsA/oq+yHoaqWfe+bwgssk/',
      'qw1aEUk7Di8x7vY+cfjvWaazcYGw8kkIwSSqqIq0pkKFz2xDDfSaDJl6OW/2GUK0wDpJmYZo',
      'PN40iJUDBRAvSgDsU5OkROGu2G8BAeUqBACbC45t4+wYxWCxxp81pkFRb8RWBvEvbXI+Spwd',
      '4NcKs8jc5OVC8V02yiq4KbKFDRxdw2OWpUCSRAJe1gjsfFrZ+2RivpKk06kbAYthES03MjXg',
      'cfcV3z2d7IWanJzdcOlzsHzPe1+RoUAaqBjvcqPRCGRlk0ogkYHyWYxElc6574iVAwUQL9iL',
      'CXr7ES8bepftAQGPywP/d9GSpEmS7LLIqazl4rgN1nkXN5KqduiH8Whu3xcBrdOAn7IYnGTp',
      'O+Ag4qwKKH+y/ke9CeZL6AnrU9c0pux150dHsDeHtpTPyInkjgKI7BofprydvpiFNd0nlAi4',
      'J4SAEYr3q92Qn/IiKpnLgo6Ls/GFb7q6y1O/2LL8PC2zrYU=',
      '=eoGb',
      '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

  var pub_sig_test =
   ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
    'Version: GnuPG v2.0.19 (GNU/Linux)',
    '',
    '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',
    'yeSTTh8ZnzRiwuUH1t90E7w=',
    '=e8xo',
    '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

  var priv_key_rsa =
    ['-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'Version: GnuPG v2.0.19 (GNU/Linux)',
    '',
    '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',
    '=lw5e',
    '-----END PGP PRIVATE KEY BLOCK-----'].join('\n');

  var user_attr_key =
    ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
    'Version: GnuPG v2.0.22 (GNU/Linux)',
    '',
    'mI0EUmEvTgEEANyWtQQMOybQ9JltDqmaX0WnNPJeLILIM36sw6zL0nfTQ5zXSS3+',
    'fIF6P29lJFxpblWk02PSID5zX/DYU9/zjM2xPO8Oa4xo0cVTOTLj++Ri5mtr//f5',
    'GLsIXxFrBJhD/ghFsL3Op0GXOeLJ9A5bsOn8th7x6JucNKuaRB6bQbSPABEBAAG0',
    'JFRlc3QgTWNUZXN0aW5ndG9uIDx0ZXN0QGV4YW1wbGUuY29tPoi5BBMBAgAjBQJS',
    'YS9OAhsvBwsJCAcDAgEGFQgCCQoLBBYCAwECHgECF4AACgkQSmNhOk1uQJQwDAP6',
    'AgrTyqkRlJVqz2pb46TfbDM2TDF7o9CBnBzIGoxBhlRwpqALz7z2kxBDmwpQa+ki',
    'Bq3jZN/UosY9y8bhwMAlnrDY9jP1gdCo+H0sD48CdXybblNwaYpwqC8VSpDdTndf',
    '9j2wE/weihGp/DAdy/2kyBCaiOY1sjhUfJ1GogF49rDRwc7BzAEQAAEBAAAAAAAA',
    'AAAAAAAA/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQN',
    'DAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/',
    '2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIy',
    'MjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAAFABQDASIAAhEBAxEB/8QAHwAAAQUB',
    'AQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQID',
    'AAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0',
    'NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKT',
    'lJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl',
    '5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL',
    '/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHB',
    'CSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpj',
    'ZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3',
    'uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIR',
    'AxEAPwD3+iiigAooooA//9mIuQQTAQIAIwUCUzxDqQIbLwcLCQgHAwIBBhUIAgkK',
    'CwQWAgMBAh4BAheAAAoJEEpjYTpNbkCU9PEEAKMMaXjhGdgDISBXAAEVXL6MB3x1',
    'd/7zBdnUljh1gM34TSKvbeZf7h/1DNgLbJFfSF3KiLViiqRVOumIkjwNIMZPqYtu',
    'WoEcElY50mvTETzOKemCt1GYI0GhOY2uZOVRtQLrkX0CB9r5hEQalkrnjNKlbghj',
    'LfOYu1uARF16cZUWuI0EUmEvTgEEAOkfz7QRWiWk+I6tdMqgEpOLKsFTLHOh3Inz',
    'OZUnccxMRT++J2lDDMhLChz+d0MUxdBq6rrGoEIP2bYE9AjdR1DNedsuwAjnadYI',
    'io6TMzk0ApagqHJcr1jhQfi/0sBhCCX+y0ghK8KAbiYnyXPMQFa9F19CbYaFvrj/',
    'dXk0N16bABEBAAGJAT0EGAECAAkFAlJhL04CGy4AqAkQSmNhOk1uQJSdIAQZAQIA',
    'BgUCUmEvTgAKCRDghPdEbCAsl7qiBADZpokQgEhe2Cuz7xZIniTcM3itFdxdpRl/',
    'rrumN0P2cXbcHOMUfpnvwkgZrFEcl0ztvTloTxi7Mzx/c0iVPQXQ4ur9Mjaa5hT1',
    '/9TYNAG5/7ApMHrb48QtWCL0yxcLVC/+7+jUtm2abFMUU4PfnEqzFlkjY4mPalCm',
    'o5tbbszw2VwFBADDZgDd8Vzfyo8r49jitnJNF1u+PLJf7XN6oijzCftAJDBez44Z',
    'ofZ8ahPfkAhJe6opxaqgS47s4FIQVOEJcF9RgwLTU6uooSzA+b9XfNmQu7TWrXZQ',
    'zBlpyHbxDAr9hmXLiKg0Pa11rOPXu7atTZ3C2Ic97WIyoaBUyhCKt8tz6Q==',
    '=MVfN',
    '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

  var pgp_desktop_pub =
    ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
    'Version: Encryption Desktop 10.3.0 (Build 9307)',
    '',
    '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',
    '=dVeR',
    '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

  var pgp_desktop_priv =
    ['-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'Version: Encryption Desktop 10.3.0 (Build 9307)',
    '',
    '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',
    '5g==',
    '=63Nq',
    '-----END PGP PRIVATE KEY BLOCK-----'].join('\n');

    var rsa_ecc_pub =
    ['pub   rsa4096/C9DEDC77 2015-10-17 [expires: 2018-10-16]',
    'uid         Google Security Team <security@google.com>',
    'sub   nistp384/70C16E3C 2015-10-17 [expires: 2018-10-16]',
    'sub   rsa4096/50CB43FB 2015-10-17 [expires: 2018-10-16]',
    'sub   nistp384/102D9086 2015-10-17 [expires: 2018-10-16]',
    'sub   rsa4096/DFC40367 2015-10-17 [expires: 2018-10-16]',
    '',
    '-----BEGIN PGP PUBLIC KEY BLOCK-----',
    'Version: GnuPG v2',
    '',
    'mQINBFYiIB8BEACxs55+7GG6ONQV3UFYf36UDSVFbuvNB5V1NaEnkY0t+RVMigLR',
    'Zdl0HHsiaTKfKs4jqjLQAoR6Fcre9jlEhatotRg3AvHV1XYebxRlzdfXxyD0d6i9',
    'Quc1zbca0T8F1C5c7xfYP5g9iKWn5yFtHC3S7mLeOg7Ltx84bTo8AF7bHGA3uIQf',
    'uCtE8l6Z57HTeaf2IR/893jLOir8lvmTef83m/+e1j6ZwmKxxZO2s+aGKre6Fqsz',
    'Oo89CpWKNrdZ3IN8+Y4udZNlr7u0os7ffY0shfbLrqt+eVEu4EHfbpQTJxvalZJK',
    'tEnGtV8S7Z3dcPcimxvO7HZu7Wz8VnRzY/AZtee4fC+i2yBu1rWKgY3V1tFKdxVr',
    'KDnmS5MBgBAxv69mM3bf8QPinL4mtIQ65/Dt4ksJuysRmGwQ8LkjSLQCMMepnjBs',
    '/63wJ3e4wN1LCwnJonA2f8gZQHNeGPUhVVd/dWFDtmQaLwKFcI0GS/DiUPBIJir5',
    'DWnrEedtlcSLlwwcUglFsG4Sds/tLr+z5yE88ZrDrIlX9fb9cCAsDq7c8/NCzgvw',
    'kFez14sXgGhMz6ZfFzM49o0XwlvAeuSJRWBvnKonxM7/laqv4gK0zur3a6+D6qCN',
    'vt9iWO/YG+0Fvhmyxe34/Q71nXWc9t5aLcokmYLGY1Dpzf9oB8hDRdMCAQARAQAB',
    'tCpHb29nbGUgU2VjdXJpdHkgVGVhbSA8c2VjdXJpdHlAZ29vZ2xlLmNvbT6JAjwE',
    'EwEIACYFAlYiIB8CGwEFCQWjmoAFCwkIBwIGFQgJCgsCAxYCAQIeAQIXgAAKCRC4',
    '5BBcyd7cd8MzD/9YdMVZniQH4qBKxLFIoYGfLzCEI0S9IVUA37wrZ4YiRODSJRMf',
    'El6oVfTO/g8xpeQlDgHj1w2IDoSkeQrY+7rf9H41sGGOBDGXSQT+7Z7XFH2mPPvC',
    'cqYqR32BDNDkO/LL1BzzRlQvNmnGHxo098sqTgb7hoVsP+qFoem7JUMpcAV1KrUo',
    'P81haV8a/25ouWFZu5P68WFh861TyIjIYLQCns2fG+zlKFGN9Uynv6E5+Qk7dmni',
    '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',
    '=Q/kB',
    '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

  var valid_binding_sig_among_many_expired_sigs_pub = [
    '-----BEGIN PGP PUBLIC KEY BLOCK-----',
    'Version: SKS 1.1.5',
    'Comment: Hostname: pgp.surfnet.nl',
    '',
    'mQINBEjaaZcBEADFRLX4hqrrQmA4CSfwwbtgJ5y65G1EsJzl+vLpcno5kbj2bkXNKQyJ/DKS',
    'F7SrTJITrR34i/XfWMS+R+nmCPioUfOMWZ3rW589GvJeTk2TnDrhgOa3Zhd/I3ZSNdM1h5/N',
    'k0o4yRNYfF/c8uPb6SgdEdJPeypR6KNH5WUmPLgS9IZSAg8UeuO+6XWhjnckX/RqB0bRK1ck',
    'pszm/dbMXe4bqYna9t8vFIPqxLgOCSwK8iHXX/6dp5usAiENJTeKD2FRfp0wvC9oXX2C1frO',
    'tkd+nFGcP8s8FlImDk7kcMT66/3xa0yYXX6R3DzKr/Mxd/59AObsLyn/zKRPZrkS8iYTSJBj',
    '2RiKscwHjaVjWDnaoHGn57IJep+TP8F3u5so5fCU7jvGdGFf4KHqm8aRF02FMnlzAUWPY95X',
    'lvXLW3X/7nRoeeUNqCliz6oNSWd2rYA3GiIQbnnK1OspRMDJX0hm13JXtHJ3/zt5+bRAx6O9',
    'qCIRJ8sZHwYZqiRy/TeAB2pcjJonlkRXCKv+hPs5RyXJ4hGxQ4VzWvrsxBdwoUE/i/08TEHI',
    'Go1BYO3aDI7S5qdGS5FVEuJOqNpsvQBWTaM+se58h1nzo6AHqUPylhxFB9JD5W3jYQm6Zm1W',
    'YLXT5Qv32EZ/YVZXIfmy7XQhRHpnByEVBkTMpNXp/yO4ievKIQARAQABtCBHZXJnZWx5IFJp',
    'c2tvIDxyaXNrb0BkZWJpYW4ub3JnPohGBBARAgAGBQJMkJ8pAAoJEPDcjgCyjFmVqnUAn2R0',
    'YLuvi5OOvZqOS5gjfbrI5+f/AKC35TvmuvmBC3GPpuhzSSft2YN18YhGBBMRAgAGBQJMj84C',
    'AAoJEDeV6MWh5zK7emAAnR23IjrT2QWsgRmEG233QZLFTk73AJ4pNFJMbny8S1N/vKceY7kp',
    '0b3P4YhGBBMRAgAGBQJMj9f4AAoJEK/U2aFyX5baWJoAoJ9KiIiH9LQhrIM4WmzgvXliTZk7',
    'AKCB8xoELkbOT3Ki8tG1XpgaPamG04hGBBMRAgAGBQJMkSjEAAoJEHzFRR6iRMhYoy8AoJmx',
    'mnni59ZQmahs/ExAPR3IVtafAJ0fxBIUhW6RloNFAJRayeCeMzE4HIhGBBMRAgAGBQJMl2QT',
    'AAoJELdNBMI86NwC3j0AoLTYGT13jgIuM/mLG8gRjVdXtpRZAJ40Got/r3X3eYzsvw7WPfJC',
    'BtD2/ohGBBMRCAAGBQJMj5U2AAoJEAPuA6HOXVToDCIAn15jfxWQrdw2mX7y86OALsPLjHVT',
    'AJ9goQnSvay1scdvup8ZrcoIJqgzEIhKBBMRAgAKBQJMjfl9AwUCeAAKCRA7Q+sY7go1x7nk',
    'AKCgkaJ6LnJzMJwdCky9mF7q8HkkmgCgmqGB0UvotcbNxl8jGEKlIoZ2/KmJARwEEwECAAYF',
    'AkyPmoUACgkQo6aYZEqvgs5a3wgAmnmHLIjeZ7MctXQhJZ+RnF33HWsodbyAuWkwv7Hp9/MW',
    'XF8wZ2LiqxKHA1Dh3IH9hCoSnTW3fUj8O7XSlYm/BDCpqpX6XSjMORbdAgujNlqHPo2YF8GW',
    'OXpMERw3Osj43+9HjtcNKsNu1zjvpZkMUDLZLgfsfA0Mzy6MaFpclAd/L/+UO8rikS466Kcm',
    'Rt/f80Eyd+ZJ46M8MDx83ICBGBDCJ3YDJudmavcVI0PhQUSc2Gf0WmZFm1IOGy8ptqgATGe6',
    'W4qDBPN6oIeP56D2k5NJf/t+Hs0lTAzC6TW4g65iFY/UJhsdkspbPlkNW2O9Lm/sPIwAeiHG',
    'lFzEcEn6mokBIAQTAQIACgUCSRcRPgMFAngACgkQ/xBWHlU8XWVqxgf/cL2izub7/N8/5vCP',
    'kiWfEkFfaw7YTAPcSpsSqCRUZ5FEqtxtSuLWeHE2Ru9IgL4AXaPVR1No1IU/snApyhHkmhxo',
    'yR6MQ8tX2GtPLBOkHvpPUB5H9BvqKYpQFVD+7RpX8GoZ1iCUAKRaA/wjt0yshgLtV4PYLj4g',
    '9anFtabsq6zj0HWKj6m7GpAWi8mC2D1DLzm5XhI2zBkGneigz5TM79L0NQiOk8edVsyfx5gS',
    '8w75AlxZg2tSSVTcJPe1lOLDK10fBpuQs4KXxXWm9pGj5CimhYFqzdcQbO72bpukq01Xivfm',
    'FBfrDGfyJ3quNeFkMWO6JN6da2JM84m2kKq8UIkCFAQTAQgACgUCVzT1JgMFAXgACgkQQrIx',
    'b3AEmZeQxQ+bBmuHnHq2pAZYvuaG8UaTm+2smak5WZ/aO9pTXnVOBf4NQG4yOy9dorkO+Rzl',
    'W87ngoX3EDr2m8Vu1HYbuvZIT/xfTF9F4F/rnMTnU5jYK5/iLO2SFbZ1O5rBtPHjMLFClrkY',
    'pb4kuYIN2zKT4fFrPFWr7bXooJdvVp7uzjy7mEFKt0+Bl4vamNSTponPS2RXBM9hnnsF9jQU',
    'VixuMDO3ookE+tAh7F8Tw5ED3afftDbcWxkb0H2o9l8nCcqzeMkqYeTYfZ0PWA+mTtsNQQCE',
    'T2Obh4n0i4PdGalwWUL1ilT7pCsFA+jzzr5svzYka9Ooq+ixEOR0RrpAc5VT4Ew/xdEQE71W',
    'kQv7+VifEBMkj4rEBxmbWOhpKWCOt2OXRJ0qwP+62ePEzYG5qk2J6zGLLsDbRdeEb0jFR8/E',
    'SViR1x0826Gi1tf1TGXgDc4mbmApTkW5eyoX9Gi6+WycbDW/ZxwzzMqhGHA9RE1I6Z8XLN2g',
    '9XHhHSkg8Sc6ZJ33iExsA/7SbYuCZAnyCH82ytp6bPM54JaL5mh1Jj/i7CDWwAY0opWepUd2',
    'JZ0TD7uiyr1vG47X2G8tebeZPoq5k52YWQkfXPLFHl15UxsIaVjtX4zDbWk/daMt05A81NoK',
    'tPKfhVnG4w5v1WFBaIMPLlh5Nez/6PiJAhwEEAECAAYFAlIjSkUACgkQ6Q0uQVDqZNVpMQ//',
    'UpaQursIX6zfdbWUb2xuXa5Fy2e1vp7WsBPtGhpER2OSG+v6CtMdm6ryWptwRK3G2w3WljS4',
    'blOv4SfUwKTp7JtftqhfMTYc0mzbzUOqdTPfGKEBgun4fRDxNAwFyGrtfKWbu42M1LAmwfTM',
    's8irZVgfcPXCpKtwgfU/upTaldRoO9s8A+IQK2RezNqNiSrFjtlF1VvBaOSVowwOB3HzODTc',
    '8BUolL/UeH6dnYXR8zMiZJq0uxGqWj+zDqa4SsRVWJ0K9/RjWAXsJZ9xwcKxzuL34E61EFyj',
    'j8fqcJv7fwxXCDoPJN15wP8mzrL+TdJeev+HtgvWQ4W+Pi14X5aIUqs2ndQcmB7l5tsjx4uZ',
    'r8JGPwVNO2U3JkJ5KRvEzx7s/ijc8B+587dIfTaYK741Dcr1VhcyGWLnm4SPQHzXNjTighve',
    '10V0wLqCbTQw+sbJSePPy9J8fFOtAIMWmc2/WNjeqkk7bTqx0cKYuanLxrlv4GQdz+W56qBY',
    'HteFFjxdmCE4tgFdMbzDIwTo6iGBJdvOnTUgXi5FOWL9uwVL6KnbtNHk0DJZtXubP4jLXfwZ',
    '3jPfe17pk2HnzaK7yxkP5DKeYExalGUj8jP74MaUIXQSyDY16YkERU3csMxejqJ0x+6eC+V4',
    'vC9KTeW6aD938GgurvnMoFPAarp0BYScXpuJAhwEEAECAAYFAlIjTa8ACgkQdiVFHxXISzI1',
    'mA//eT6PlzFAgtwicZYCLou7DtHznnBfMWjw4vPNX5igH0LRftWuDzgok/CDkLSAUa8r3VkB',
    'rPLovqyriirbs2r7gRAz6JIgnO/mbFWiMUi+g5g2fkhPpwWBNGUrfyhArJ63p4poQh4rOhoJ',
    'ePNKF3fL5cNYnNn+d+sHuW0z2u3XWwyGp8ERgJHe1T2D5qrsHKUYn+ySrGxwcXdG7h/9/YTu',
    '6RYgLjjKG8vC6HFL/pRLWdtgEQ2aefYZ+oRW2vvwk7FFNikiJlqSE9Ur9SdT8yev+Vk8k8Kx',
    'OKKo6g+hC5aaSZB5obr38z7QHAuqRuaYhnDiruwRjQbbkURkGz9Tz/q7GyJmapE2lbVD/GcW',
    'XqKgq4os+UToQL/MsZG0b3jtrkUbLrrq5sID5gWJvBcMTX7Mc0fidTnoTLZ9rgk+GUeEpNbQ',
    '4O6H6Ro3Rm+kIuK3Ln0xvSd//4B6hsPWb+FzQLTAOWwAQCX+1Gu11sR9HMlbYGz9JpN32Ydi',
    'duWP+yhH+UrDGiPgOWaURygB4dPdU+MPlFvKtZaOPECEjwDVnrwdceu4is3BpuC3M4Gim1cr',
    'U05wqzmMh7Ffg8hLLrOnmfkoNT8RfKwrZNgwRl47CUSOII8ZRdCY0EJsLYwGmZhsS3lxKjE8',
    'Tl8rKRzaXekkfzk08TV+44J6BK2+gFT0fOEngR2JAhwEEAEIAAYFAlDypPMACgkQVa0UFSHn',
    'ZN+ViBAAoVVxmZRoQZfQcVA4hI+Fsx98lDLnL5K8VR9EFsK36biZdlmfsq1mWP4MXvCfTbQ8',
    'eM0vpSX1SuJnK4bTDSHKxehyYfbeHDIgVGjhnc0FXunKI8LMJ+QfJOUhJx6hSTl+bJd8jiwB',
    'DGrOC+eRF8uvEcoLlfnvD0qgzulird9blG3ANssHXpmX7Lu022r8dmpgdbBWM7vz2cxSOrwh',
    'nqP8HC4O8qBH//8FpHJCSARoqHK0QN0XQJSmnxw6jNq47iZ5wQZl5srTioGb2iSBGjH9Flmj',
    'qq6dxnNzClrnAZdqmE743gCB9pdf/axlDFQd0HXTjpCefjXsZ3MzvqkMVZ7vQs+QVbVbHC8w',
    'wMCJ6kLvl2VpHgzkFMGSEJqn4xyrarbMTi2aMJdTp4SiNQeWArYNjTJFPOzffReB3zzv5XYY',
    'FeDVvmf+6BV41Hula9rrXCGOHHDQ+TqHTRvvCtmdEu5d6UPChzyuK0889iE7qs9J1IVgqCn/',
    'ztBvI6+7epYwvQ7rzMQWUbQ592I2h2fQc7sX481QpQpu7Gpir+U3OlUbQGBIKZOr1j2DGJ4c',
    'G5WzHDFzHr6c3cC4LODxkYGfks013/QR+Ytwh2o957IsKFd411oIjuQC2Rv5+Vm3LtnBokF7',
    'izZDIFitOF2djsQdJz8DZvyZaogNV1cA01Op29G38IGJAhwEEwECAAYFAlUT4L4ACgkQOsj3',
    'Fkd+2yMLTQ//UM6ZlOHbQ2xfWIXtpXPsMznMPFW6adT/REyQvIrBIB3pRBtgG17buZetEgkB',
    'fVcxEZi3S1VGsNB4WX1lVkBVNf5HgobFus13UpJqKf2UCMGkDWPIm8uDGcC4UCxh01GC8JLI',
    'ZjbKC8v+KBa9af1mbreAK6rx/rd+hvhXSeRHfM7wNatZmKvLWzomJcuhbML+JW2nMqBFTCdO',
    'Ts5V576aycWBKDlB7Udwie/8EJQnrB0DQG8dsVWFb8G4NmrqNj+6nc1y0oBmhyebeOpLDdxy',
    'JzwEQsEUL91GzxQql1Vb0ILhzPnuI1rvzhMgxG5LKzrot2XaNHHVnLbPb+9umYb7Mfx+OPDD',
    'Z+bOFBUbvCvIIdKcqScpFAhwCOUycafX0MzQoRUKwMs9DeNgdeWymRx14A19FSx7+E0ppEyg',
    'WoauvoQLtGJn4tnSjxw+k2J2aV8njfDHwoHjIS7EYMa+TY39jKJEGrPzjqiP59w/ZfVoEr28',
    'UJEd0YPGNzYsmI06sVvKsFq9dTJ6Xsv0pROGpbtji4VrXpGO8EresoDc8hiD37mvQFCA15Qk',
    'c3og+Lg6UpwlfTTAnR/InjlBG6NUa/n9E2eHUVa886RyUNAn4kLehJl3RgeqnGIQCuT5XsXg',
    '4CA3c5wWplFxEFIPn4E6RrTKnAs3PMkidGDdaLaIGbvQpiGJAiAEEwECAAoFAklaLHEDBQJ4',
    'AAoJEKR8icvBZ+/vt+kP/2QgOiW+XPdrH9xmRgD12dpOkC/lRlaKddPanEj8wMNO11UMpH3J',
    'wrQtRWEryLm954Y2cOjdkXwtEd59ywbegGmRiyalv8fvlEHlgQHXa3kYimcqsSVSspX6iwRr',
    'LltR2d3Qk3pgHWP5uUP9fFekISF1RDqxkzKoFcqiQJZt79DZ47EdIdgOrDpJWekGtvLpqRyh',
    'uddm5PJjjfK2WuPAFJ9TtsQfbcmTmrMsamYACiXmcgynmDfH2gSAv/JPKSVGSkcM/JOk7EuG',
    'mVuh5WDGKr9iObzkVQL2H70piPueIN9FVOKG+0WIlIAwhnHmzYw0/WGjfxX9oXIveq3C5ztS',
    '1QMmvEB5OPiUqYhhSsIwu1UzGOO/BNbkx86B3Q5n+Kq/ioyx/0HUHUyHjivzn/B3iY/f1bX2',
    'HG+U0wy5mpU4sXiP4q7QQ2ok5J0TrhGKnHE+C7HYTzAnLeN9pWUYbqpEfzcfWnz4kzneG6Pf',
    '21xXcwYJsdnfO2vRnmXVQvUBaGAFjMLr50rBoZd9mrXJFLdruy67VXY77DQFq9udhNpa0jV0',
    'O91+Ia9vm6OPdjztJGwkgwyGz0Cmq7DWMY7JTCWauDalZCII71TOuCiBtNtXfDCcaKfqyzc/',
    'AeQkUUNxz331MSI+88BwSiUKyteWPuTf2B9LJ2s3SKxQMB+5JCLIUYkLiQI2BBMBAgAgBQJI',
    '2mmXAhsBBgsJCAcDAgQVAggDBBYCAwECHgECF4AACgkQKTAQAQAAM0RlFA/7ByMGATtbsXLO',
    '0iKsryhdk8m8I1Up4TMJWNwnBhT1mXfPgZdz7ipG7hpqG7bLgs07AL2dTThsVTLTYW2KMzWl',
    'bxRUA1TBr1aL67WyuRpzQ/HatN8Zif6BBd3DlPifsYgyfqfjAEdAqzrZg87+HgswTffSJxjl',
    'ihONSvWIGIv9Mz1WQdkD9K43Cw1ECaENtEWD4HMhNXsu+T8Fb/0ODqei27mUeTjwSAxGax90',
    'F/0TiZ1s8CQkm+D34NoL1Xq7bOYf6ilGdga0N3dK8xrJY/t8NiwEBognZQtgK1ZcB7Umk7YO',
    'USdLLIAC9TECAowzIlA7pkhCWLYa+yT1WZkScwM3QQdjAS9q6RkuXdrgXIiI+URSILeodzDr',
    'TYC5OBFBb5Dgo9BaKE9MYuP+ULpduSwyBPTTMJEnujXDxJrByfrE5UOPp+o2lgv4IHYWgBx5',
    'zGpKEV16iwvqnMj30AbOmU98bHtO9dEdm3d4HmwXsyvej/Gv+7mpmkkE3rl305NL+2awPj/+',
    '/yOLED3lVq91P1ASPxFg6ZQDDDmwNkTQ0JrD6eoDGz8gT36iKHn9KC8ttohUqtlovhm0xK8b',
    'ipbzzb7hHrIeCm/kGy/gke7nMriyYDEhc8EqEp+XdmAMfPEp/ODTovpZ8VBsvGt3TfE0sblR',
    'W5UoFpjcqfkAQqu9kq9FZn60IUdlcmdlbHkgUmlza8OzIDxnZXJnZWx5QHJpc2tvLmh1PohG',
    'BBARAgAGBQJMkJ8pAAoJEPDcjgCyjFmV+AoAnjy9IKwZQ0+54NqTGxzb5ZNGSM/qAKC2xRyM',
    'KAjI8VdHLLziINrIKE+sWohGBBMRAgAGBQJMj84BAAoJEDeV6MWh5zK7dyYAoIfANrzBIQM4',
    'eDRL0mXMuOT5926cAJ986qQCzQt6QQgn/0Ns7zkigo1GJYhGBBMRAgAGBQJMj9f0AAoJEK/U',
    '2aFyX5baJfAAnAg/nOsO6EikUIk6ekH331Efc3x7AJ9o7S5WiLRenTGvUjEXmd02roazdohG',
    'BBMRAgAGBQJMkSjEAAoJEHzFRR6iRMhYKhoAmwQBL0Lf98SeJHzYTnWg8eMedEZKAJ96swor',
    'dMnqO08tuvRGY/pm/yli4ohGBBMRAgAGBQJMl2QTAAoJELdNBMI86NwCNpkAn2C2YLEmoctO',
    'EPM3UzWYPOts5Lc4AJwNYg9ZgDdP2n2qP2b3lAI772d47IhGBBMRCAAGBQJMj5UzAAoJEAPu',
    'A6HOXVTox1QAoJgoMrlLj90FZilEwk/Gbk4nCMhAAJ94IVvUf5xxIpQ4y2U1zrfcQaXUh4hK',
    'BBMRAgAKBQJMjfl9AwUCeAAKCRA7Q+sY7go1x03jAJ0eAf0skWwKC0Yyl3e1/oVbCz4DzACg',
    'japgZAPpovSgTXnhH/+zRCB2WhKJARwEEwECAAYFAkyPmoQACgkQo6aYZEqvgs5tpAf+IDTe',
    'AzS3SrXdjG3qBxFlNZK68HUP2B+oNzdOxBVSwkB667ohgKEaFwk8idxncV1hXnYxbEQPFbgf',
    'yLsyJbYN7wS1u8HgaEgCloEgYt88ubO+2+p9FDKSXp/lYx4Wd/QMZjWE+jmZjek+1r+JMqiK',
    '1nP9auHFvSlIpEJKvsxe1IOC8ctriukBejBDPYHqqjIXNmXL+UsJ7BTF81KSXrD6QRCKWU2b',
    'vem0M61XnXOe+8aRF+pc6rfDe2W9OQSwrFtwYX6gqbxX3G9Mh7cj4TwBvxqAyH0yRkd15quc',
    'vtIFx1UPFEfumKEEHVI3QhM1ymF9HvM2Fkco1+6WYsWeYB0fhIkBHAQTAQIABgUCTJCQtAAK',
    'CRAChoMH9nXSZ0yUB/4kklK8mSci9yY/p+Jp+PVA5+Ts6GysWeOkk9yuRB7vs1jjN3eNus4T',
    '0LkyKcVG5hp0tgGpjqErfAfHNq5OI3HAhF6TR6EPWt4IeMAbOJRNljqmG1MGb6SJc6elKaw8',
    '8bx8UwsLOtKsMLP0O2pN9EQ9HN5AErqZ7WG+oUZwTB4eHmo60KayUuM5VmX6akurWSaU9Ky9',
    'OBVtOXHgxHtmV4ZcszzVWOTpNbFVHLZ4OA/WeF0uP0H8tn56dn/qzMCDyhRv+U7fOnfyr+/b',
    'bWtNwKqdVXxA4D6YFTOoAJfY5nZukLL9HDNcRngiOyxj/XCrKRpDbyqJgoV3vJ1MQ31h4cdX',
    'iQEgBBMBAgAKBQJJFxEyAwUCeAAKCRD/EFYeVTxdZYFXB/oDxz8Sa3k5AZ85deLqvs2rsUGh',
    'aSjEz3ur1SFIiEgIJTlmCiJlhqMBoo0g8au/J/HQzOSvjIcB9wSuevPyWCEr19Nqju1ZXvUG',
    'u7dqf68j5stNMb9hyYv6lfI0S/sOFV13RsotkPqI/HhP74wLVGDOvJK8vfardy9BRRchOS8r',
    '/Aqkv/Y4IOlJhA73qmhaQ6/INBZ4nQVWkFZWje7M2bMZ7ly63XtLsXqXsooW6kcXEjY08Yzi',
    'FHdElmFZzc3k0wPVNWm0BO/442ig42sLJn7OqrttF9/Nz6YVTYAZQwmU/EG6Ay3j0F27gLTc',
    'jt5uwZ1C6oDKZ6bEuwfOefHHE5LhiQIUBBMBCAAKBQJXNPUZAwUBeAAKCRBCsjFvcASZlw53',
    'D5sH9Xdq0OMT0jGjBg5KOB4M8Xdd3ujH3NHZEPLCndDFAFsSReKWT9JNptbKXP3nHzxxSppM',
    '/qxGuIfqGeKkAbs1AJxFPwlLYYT+J9n1TKKpRsjjYL8Bn9LAdLbDa0x5WMT47d9xnQm1d1e9',
    'wXAF8IF72VBADGb/qFl+55wBRT+0ZEFkia28ssj6ZAZOZNADUYT1X6D6YMGANG3SBXnUkMMh',
    'fjsulqa0okYgDOpy0gvrVeJsZxqWYJY5KJur+LfcHT1K7jhv5YOQzA31+7Dh8xCjhbyqhtGt',
    'iTxvYbx4FzyAareDHwcYce027dT7GaUmF32u9hwtFYn2kwCZL2Flg37Qr99ac+ezKqjgSSYm',
    'QGt0KrfLFF2/odtHMING8zg9fog+FZsoG/Pm4QEJPKI9EWoRFXsFdzVhWDEZWHYbOaaWJZ4v',
    'a4aCxNLLvG9NRhn1djPWlneElhmzjhRykG8Nvs4CWmJ8gS6/i2Fo6EvgHwzYplz5uh46Fdg1',
    'B6f0/j1hEMgSjQo3QXTiDvZX5td4yayLwySDBBS4a+QAbqBeGWxSWNVSlAIFU4oZg8whmhu3',
    'CCTucJChf8pIiLyIWv0y8NCLs3UG9JV+W8o64jamFj0yvcg3iUdUr5D/vC+PNKP6kkNcWN/8',
    'WnDaBO3ILLaF2BQ2+ABz7IkCHAQQAQIABgUCUiNKRQAKCRDpDS5BUOpk1Ur8EACNKNvTVkJ/',
    '6JzbgUalfI4gLE8krzxzwDpSxfCg2k9m5UQUCe3DjwSxiOUflAraIbEdM4/RoAVZ8C9TiHuG',
    'WWuSDk4fCbp7hs9vyAYz31N+981dGYJfhFB/+aMUFnlXQ8liQXK0LUDSlemMjqDRtYHwpqJv',
    'nGhHMudTywW1cWt8/z41qY8Kz+6hjUdJVoejgUYpU6sQHb3rzM2SKjM3ZbCm3y4ogoThaCI9',
    'iJxHg/8UzZoaDn83ZBSFcVO2SNrIRlYBl0LioLnoKuDwWCzcD52Iaj4cwTj2wG4c2ouN/KPw',
    'nebaLwHqRxL6qJSGrQzAzV3qcUiURyd3aDRc/vZSfVgex4uWB9EgbZVfhPRd+Aswtxs16S6q',
    'Nzx4LLG6b3+t7LxslJV5a226mk228ZK8jkCe1pHHrd8L6PQ5oNknC5kaYTUS3y2aZFRGK8lx',
    'UtIVW5an9Vq9sexdsCKCTgWcgMGpcS5bnIAkvCpKUVpyF84JJdL9ekz/okVZASI2fdQmEM+x',
    'wk8LqGczhrPWfr2nQBsVKTnl1vrNbSem1P9D52fGt+qMKz9kUHwXIUMUOpQnFXiYnOLXwHGh',
    'Q3Bg9MnRKjSOlDuldAmFZQkATXIH5esCq6GKk4leKV2Js/rWxHcj6ULwPTS6lvRs2adnzm7z',
    'p0E4ewyjkH3xCCcCLZNQTfgvcYkCHAQQAQIABgUCUiNNrwAKCRB2JUUfFchLMhEZEACeDKfm',
    'cNuNAEhigjsx22nVeNQpNgYqRkU5FoItt7C4rH2ZDUvpZh3fs7fs+HCqE+2XdxRE+wugFHt0',
    'Wjv4Iph5T6e7CWRat2qexsMNh8BB5k8w29fGe8getAVIv8jrhLc4wTFBZb2PQXQIuvYcSl2W',
    'gx6yPfosEpbVfxWV84V+O+2Faxfsy39N/qYC5vqpnMQy79QxrF76zfp+I107gZgbkyiWV88z',
    'CMOKs/JGbsTZ+GWzBONEKvRvfIalDLvnz/nQV0jYGOAhwPOTDhtagIJnvwZsfdCCYhbPU9v+',
    'qFovwDUYdGK+cc7mSq0TX93FY1ItFsYflvkIJt6cLh/0fhgxRtC7qOfqc+KEXHxtpLvy6yQo',
    'AiimL7ft6i1BXRSKQhuu2eJd4L6urq7cix2h4w998lQUAunogPL6SXqDwzwx52TZLfaQZRjI',
    'PO4C0VpguKw4dKBnLzg/pNlaoYDk2fCLDkip+JEl751g4k0HqyQCPtYOkgpyQapIu+TdFbBE',
    'OZ9Rbcv1YWRCDM7RElZ5M5x6SD/cZ0EcsMS6vIDsUJcowNq2zqd+AOMlb/jeOLfTYkJETEhH',
    'JneP5HuH5xjRe+vQiHOuvyeLc6ipGa/UbYwNOetbrjHD1rv2V1ensJUfRVnNH1sYiJ06Hgr2',
    'bAM5zWbA11pPEVd9Yz3MceUZJdl1VokCHAQQAQgABgUCUPKk8wAKCRBVrRQVIedk3x+1D/47',
    'utZR6egAOcyjityyP9qtyt3l+HJYVlCxVNf9n0Y3va2qGmNn0sKv7QfCOfmZRL8jusBJeZ3I',
    '57HOcraygCfAkm5Gf6tfVHWSNkaosoG4bf4rV0LLLwlDAZIxxgts7XoQbZReIyAEeK30M389',
    'WM8+YmHANKWFdHQDQT1/0PK/AiVDLevPHyjx1u4tUaDEHbZZ+BGpPbIOhLrzX3Ca3lMWxX7m',
    'xdlo5dpmwGkftfi7C3HlFbJTQVDSu5dvAOQvKF40JYUAdhjwkIYUrNIwCe1whIYzYPmqaBt9',
    'hfD9Xrg4mDZfM5GA18b9b5wEANgLLzcbd/y2lHdLAytMaIuRxTc0LukJMyhLqlp3cDtL+H++',
    'PKfVeV53DIsT3ygNieO883wvFfAVQyVx/H3s4j2KuZWXJ1NfpKlaKJxAA62ikDQp7vr8A1D+',
    '4+inx3dd9VNqr4vpwRWqI759CTue4e36RkqedP7v0NWxzVlGAcGxcdVuNoNUPj5ZfNve2I+h',
    'rOl3XVxTEKCkOt154SRD7Myx6K4EmpDLZ95C0hWnDgj1VwsOALILCXuwnyyIQ7nqzb2GFjEE',
    '9CI65Vwe02JC4KSGTcrzuoSZQMB9yE6lrZw+U8GC4lMK1Q69+GZ72ylo45FO+7nyAVdOSFPp',
    'JhUGaD1lG6q9JY+HyKhyhYAkXCVhQb3qpIkCHAQTAQIABgUCVRPhrAAKCRA6yPcWR37bIxH/',
    'EACvuQOUDgoaO0eFBexa+IQBCPuKherPqgkzSW1C+gRkSkD2ufCHFN0AXpSimD/CCiX7ktG/',
    'n+OczXEVyLwsFrrHRLDo+oq5rEKagH9aTg2RsGsvydFpplM7sreBlp7Add44Meu9Em5xPUDI',
    'vu5fJcG1JZrwB7zrzPTC4SwgvWCbMVFwD4t0mCMm0jPR0LLw3rTQw7scpp4uscLXy9ZvzCyW',
    '5a9ZR0sOCQADwSvh86aYsrakHcxHKZ2QAmUDul3gtzS5A8dyoPFv+nj9TMTMH2HnppcXcfR9',
    'wWoL1MPi3+2M2D/CBhewjnPvdkhQANpfIRnvkyJeGwVRFAcmqod+H12kDK2hFOeT98NIp1TZ',
    'RsikODYzVtnScWV1GqrH/rJ6+eo9TId81jDCILDQ2StqqMFXd7Gb2H5HrFSS4Nv1CNOmYRF3',
    '66DFxGn73qf0rF07mYz4t95Ts7QVwwJdhm9vjdZhYZakHfm9imuwZWC8HIad+G+IqfzJnOwu',
    'Ugi9zck2ecx/4qU786UJTnLtOWkbyvBfezInMgko7dtS2FQxoIzJjQSX3uLPJqAwcIpBoXdd',
    '1vQZ4D9Bok095sv0hCm2DeuhMSYqE3lnMBakmkJWIfKxEuzcFSagRkPBGPlw6BY3ernj2i9j',
    'sNvDZrmGlP1SCTw4atSosT9PL21Wg+CNMZH/eokCIAQTAQIACgUCSVoscQMFAngACgkQpHyJ',
    'y8Fn7+/76w/7BZk816oLn/TOhTWchWbW+EB67NFPGkUpRU7Ff7NxVA2v+zW/EqZQLp6J555q',
    '0dd4BGAKj5b3xxCMRZG21ecuuWbLTucr2ctHPySYhTIjDRES7d8uq6wzQoML7t+MIAN2UtEa',
    'Or+2tIV0sRYsNn3/nvZQaQpPuiVA0nmiHC+h33SpM9LV9WQuoRoMfWxg82CYiPb0m4vBDX19',
    'apa5u/wBudc7uQZE+5xSMhktctifQHB1EogRGGb+Ju/dlB4JpqsX61fFchzwYAj57QrgnGqA',
    'tUtrlCCyboYOzo1MMjeiBLyuKv6P5vipEPb9IjdE5EDI6fOJCRyBcceAyW7zId17gvf/b9c+',
    'sw8jPeFR2HjfRqg/jKevhGPg19I9wX/JHGpZdQdg9Ra1is235XKOpgZhcZ0cPXlCN9qvzN20',
    'BZeFn1XDSvF//pBPIL71psYJLKh56z6HUUSLdMQ/Bzl5jOeb/09VYslmksQt2ap2wBeMlRms',
    'g9/H49X0RUtaVtEo0fJE0ymrrtFyOqZLxRGWxKylN9WUbvLOlPZ1wJ7ygvqV88y9WiQ7VRUd',
    '+p84CxzEH7f7gApGAJUVZDs9yeoJlyCRa9pU5VdeiMJXYmep32XGNuh+3g861yNWmNhNQNxs',
    'Ilmjjla+IlN8W8uRpvavtf9zp3InoO8A62BnnPY2mgJw5H6JAjYEEwECACAFAkjaaZcCGwEG',
    'CwkIBwMCBBUCCAMEFgIDAQIeAQIXgAAKCRApMBABAAAzRGvID/oDXwiTuS5YDVLqaoCQkBD2',
    'fHuUA4NZyUglkqUHlajshy2X++TCdlbLXLdAWTBvBQQ9MeyRAa3QgTOBP468OMo7BPs6BwZq',
    'dCkCn/v+5jPSUHASgWsIPUjQRvnongNana3XtnsRFEWn/WGhNd584zRYBlR8urvCAOeukjpN',
    'gaQe5uPQazFWXVqPUlqicsDW8PhjmSsRD65XU3mRUW9tvOOwsSWevSwXA7Swb5B1sQQaHEZS',
    '9UB8mLpRnZD+Pev5Ccm8dXCLbreSnBkVJYSAbu+LkKSW7+qFsomvGeLDHWbdJDdeP0/mRu9A',
    'wYNmknaQAQ9Duwqj/uqNnZFbUT9SDz+qAp7YuJZrAGyw/Yi7xZqENMshmZG+TnSAXYeqrKm/',
    'CpC5oKZswEa5J0F1KgPQRFGrEu7AhgS5QI7deXe9rivKhULSEb8tge5U/xs4cXA3dQekNUHw',
    'B3pt/+twBHAY61wwicbl6KSsguZUpANlOVEPirEFt+TqAOKGmD8aGl90nRqS5jfaxoSlydjY',
    'ACg4sxxcnXggvJITyjkKDAF5hTpONceS2JrvgL7VaK4I1Y5/tIR3zsWL7VxhbcTZHtbfxKbe',
    'revGb2b5JaFn+W1i4TyX2XgFf4JM8EVjofeLfDuV8L8PTzp5DBOJ5VzaduxChn/53+WDYyG2',
    'KoGbWlbxUjjhdLkBDQRMjqDCAQgAvuI7bbA6k0agNge7akRDkNjuvNyQrq6GtzY/8wF7eQ8i',
    'cHXFhj1zk3DZvL5JFr2Qr9GIUq9qYMCMkmabkuO1EXBTfO8hJRShNkLVXbmQJUbNZ14yZRY4',
    'tQ95H8y+Jm6E2ZGgn4qwF8IeDVgziKToGlGleeaj/RWV2NXM+RC6kOTocN41b1fLV1Z32QjZ',
    'dKMTPgraOgAmJg1msDB+Y/aPx0lU5aYDGmtE0IdE5O3nqBL/J29gbkAdrGcO2HEjyLNo3qDj',
    'rfVcQRWt2bGB9K0ko6ZHPRFh9Nn7WFMcEti2gtRd+wKPG9VnBNn9QJN1evQkLKDcPNbC/obj',
    'foKxNN66TQARAQABiQIlBBgBAgAPBQJMjqDCAhsMBQkDwmcAAAoJECkwEAEAADNEoMgP/0A0',
    '/Vz5LpQTXNAU+H+1vTH2d4Ao4gXp1sxQd+ncTekOKu7BIPr+6iXcXPQBNNHNYvoLGpfwr6b/',
    'wjnFnEl6bDg8YKJ6nmfT6QYxHb0YiSa6NoODcmoI5DphswPfAfxZpmAgwHVMxUY5ICIH/uyG',
    'AheM2y6TDyC6+fp52VIrjBO0FiJ1n8x89Z07eCZrIJi5FSR2Y+Cm8E5yAZFWiy5jcYW6pWVd',
    'a4/EXkddVL/kUhpWyC+SWBzIi16d3Oj7b+ABjROxNENsY5KUAXNapyHQDe9k8vsA3H0YrDqm',
    'vPZykOXKMB+kvcT0Tod1SSCo9jcdKWffJaMJkftbtJVNLDlpArFDMMPM4iolfsycDHl/bEFO',
    'TZMd/YKDLjIk4XjcSwfabyZSAdJ1RYxHmTSz/Y6RPKJoQt3bBNUVpYY9r3aTfB+jRhuyNewo',
    'dy2tMxToHfyyjZBoe/Uxa+NFL+Ije/6yz/L3oKcrlW0IuVnq+C/3xgDP2yVdu8b7yavKhrtk',
    '6G5mWtzMxJ4aVcLJz/z7CAIk/GXFdql8z6sdyID5eFwD0f7/9sW+WeR/bCOLdjK4kunpGPXh',
    'Z4CGczXgWpBNlaS9EHHLSjcVY0LhIzCGM/wRlfxkFmvYlMRaK8sTPqHhnyhyAbruX8xLN412',
    'NmtuGVz/0Qrq+gdN7uRNOoj/bnV5+QetuQENBFBQ1/8BCADMfFdRm0eyB6fKYA/GHzU7AQo3',
    'VCcqT/ZLRKQ6hHIGf2RPk4H7PgqwTsGFSP/ugnCW67M+iivYQxT5lEH9iOUzLqd5jG2oOu1F',
    'uNSjcMQt3Br6KK3xOS9W2GfwD/9hzDDW7PBr7zVmlKTPnEboOLuoCrRBKm4cKgPensn/nSE0',
    'RasgMI9vh4ECXiuMU5eJkvvIiA1RuzkjSjbzT0kj0hr8z7kV+zTOCrvpsSMPbsO2ctigpwqR',
    'OKMZeAfZVxE4uECC9jR7jp/OoId7dC9xH3gQnmKBO2j+GJC3OkQQCixHp6hE02KNO3DPcMzs',
    'xDJ/MTPczKNZcczELnsc+Ofbzp7vABEBAAGJAiUEGAECAA8FAlBQ1/8CGwwFCQPCZwAACgkQ',
    'KTAQAQAAM0SlQg//dxds8eavW1ku379sHv5KriwxAWnjtnn82oGyw3VitE6eUCKQlu3NKP4y',
    'JstXAocrOSJI9RkwyxeyNnPYyxdoYcCeOSZv0Bp/CPqfVmS8lSkMvoC8PDvHS1uRSd/U94Ea',
    'onDFDJk7UHXyWLPlmvEdLzYv1VFgaaP3osEevLIdDN0AirBWqsog7VTxQ0McuEbdphi/DgUr',
    'yq3f0TbzpqTofRQSmJPdHDhpKraAWyPRcd3/zqWQD479S/4PEP1TB0ZhHO8pfNS3e/ao3LQ4',
    'AV+P6lzBaSaXjxkQY556v//BXlLfYO2PDEP4iruBOsKb8Td1lpR/N7bPNDhzaePpZErtREbc',
    'URzHfdM9WAWx1b6YC+nPCZbMFayrQySDiJjKRl7ECmPbr4Rly+RZUTEFdl8IwrStw9Tn+K0R',
    'WZznQNXgHXub1Nzdm9JkoOysckteuvKX4iD/OaYe2TpZhb+2vHbK0/FcYcBTCmKt+sPDXJFB',
    'j6aAoHsnLgJhAD0HjvTRQ1ReWJw7/GQXWAd/BmtXUugDhuRjGa2E4QNOg5LFrHzPr5YzAowb',
    '3BOzDfzYf/NJ+K5PLunnydRgF8+Ii6b8mfgjxIKto2ktOZI2h/qMtrfoFTJrbC8B0MTnXWLG',
    'vhHfZMqkMbV0u3gpCWTFlfQokSNsq5P8EompQ4LXF5fPkDScFFC5AaIETI6ghhEEAMVT7o0p',
    'KTJFLMlD8UNPXrtvcXP+GMKpqINkhGeFrYLee+xjDUKWA8QTpSvLWLC25+SR+QB8FuC++W37',
    'KkyPt/qGSdFd/KbUg276LGZwvR4qY2lYfkognSzAQP3WVsFnQyLdEl29U5ekKUC24n/iBr9t',
    'aegVtgwbIwTT0rUDwUrLAKDGjtx5zArRlmmKjpQehHMMeYZ7ywP/bfFfvGKuiNYX6xTOVjXM',
    'nWriIgCMClJbrv027WeYysCFKLHw1TWKIRA7U14+hEPn/bofekogFdu7CvZfgrl1equAWbJb',
    'JHrshFfFKAB0Lt+1NPswSmweJFMD0tw/VjFiUAmZTyciMI+xg+IwjbbtLPRK37heWO+aQ4ka',
    'GSvLB9AD/A74voTaSfRj4nOblB6GJ3QmNZjwE6/aXkQDIoAP8VsEWd74CNnqD1wo4f0ygf/4',
    'MqX+1Umu2sPD18TL9LSgtenXvuydr3Mns+EZU+JAN5bpgYzNNQ1A+nQDdQkTxUWrrv/cpGJi',
    'D/F1mWIm7YLGk8FgsFsXiVHtCtV+Bj4iqSNYiQJtBBgBAgAPBQJMjqCGAhsCBQkDwmcAAFIJ',
    'ECkwEAEAADNERyAEGRECAAYFAkyOoIYACgkQf41LQiDQqqzTtwCcD26fPDM9UfUZdLXyicKR',
    'aqszp/MAnR6MDrZZQXueYWZiu5qEbTxiuz9rhX8P/iDuYOsnu2cqr5QM6ef4qEpYpEklGDDL',
    'kZtqjO8SHfKnw02u1/2or5hSP1BgTI2um8mEh+wHTr5Lk0vH0tIQM3vxHK0yuZPMvY5woZ5Q',
    'si3NiOkhpxTIHm9qgPXHUHq27enklQkFMZ8H/ZOeU5fs3/RbBUcFWctGDbTnH+VLieeZD6qf',
    'JNUmimIuQgZ/WzofdFIN2C4LbEuYn4G2guP9SOW15ODQqTblc2hq6s9haHI0q66sZVdNlNF7',
    'DGBMByx2GrjY+2eg0+CmnoyWWrWNLzD0fZZ76BJADv1maII2LTTbMeCJlX9+3lF6WSE9L//j',
    'az4aLBDsEBu4uhRNLoLRhnf/49WsYdszSeMit/dws4NgccPh/adg5htiylzJ34EvGSvLyp+0',
    '/w/DSjr+CzA/YE4djj0cYb4u5+ieGnQd0icH4jbSDuvDsjBxAltgwS7s8nC3qunBnyQkGOkU',
    'SJfb9aDyirWe2tTofeQvkVYzBhDoFYJW3SUhvgfHn7MAt4ASnZPPuoANy0fgPVlTT5DJMO8a',
    'vyCBODhxMNxy0R3TIsDKhJC9Q6nK9sqdrjPESQmUB7rGmBpgsehAMUel4O2PunzqpbWxbJhH',
    'JxWGLfn6H7OcatvQBZ6JSEmOQeKC5S/VI0IKOhdWQhnYVIV2+NFEV5YUDzQHWfQPWfKpXC2q',
    'kYaxuQGiBFBQ2H4RBAC4HzyqrT2LBSPd/TI5vGQRkq4hMWkUpauNfk4yeBboSX+VKogT727a',
    'wjqK3duT+9i2tJrXuWtpcSxfd/fpxzBJFKPc74VFAxv+qcjhpcFPqGJqi462ZJ95+xS3OgdD',
    '/APNYbxhq8G/kCTajhvFhJa3vc44Yujcx7Jfrfx2aAPTcwCgl/+rgacSHreqpbvA6Uj/hSyk',
    'A/kD/2xzJQ2xk4qLbgI0GR8qUJyD8N0dmnHBjli4LkBGDTfdqGgIF3b8dtTqz0L9KXO+/viM',
    'tVC126CEeKImRfi2MlPtb7G5hMUUTA/1P6IaQ8shmLRZm4Gf1BBW0BD1cgdZEDPLkKH+USpj',
    'sL1M8EemPUsbjN5g4iVNI7oAh7e46MlRA/4nYV4vSw+4I5joT+ulv5T7bTDqB4+bDI7ErOI1',
    'oRiy4wuEs+M5WVEfUln1RvZgPPKvq2/QwcGbWzR1TMeejD5u2lPqiKoyzm5RIAsJoRWaF3cy',
    'dzT96ZNDddyExauj0HAc89DPdmUQFkQ8NdrBXxPUvfd9MZfBzeQPyYqDO5Ky04kCbQQYAQIA',
    'DwUCUFDYfgIbAgUJA8JnAABSCRApMBABAAAzREcgBBkRAgAGBQJQUNh+AAoJECS169uLmF75',
    'BR0AmwXNQcxRgqEtu60/P5zFHgO7X2DPAKCWVKYZa+tfWZK3i0zj7buK4dc4Iaj2D/4gLUyv',
    'FT3dVMF2HXOsrvU13b51D0BgXt83aPGQr/qu21pbz9sRvF3c8ZHNU1xYDrl1hNEUZhuSZ3Pq',
    't/PqlAB3QESGoaaD6Gs5S7HWA4eMDqwRB9kv6XYp+rmvaoQwOUkLkdt4s6yD9oeaiqQZgzgJ',
    'RknOfw0bIBqlwgtJW8Cua2ck5DXU9AWjgSaBKtNTOp5sTHgcBpY0SUxLVKxKcBojDGMdTee1',
    'JMAPFja2bNQmXpjw1D3r4uvTxK926LrMpgOD+2FCwfYOa/wwvMMfV6XgZGcFBorQg8z6FlZB',
    'K2wR+IhC8CItpA+VLeqDNIYQibnm9bCSi7letvawqwOn+i0olRhRZjcvEOwmAXgs5FJ7ZMFj',
    'XyGI/ubI7txwdxA4/VyqmbmlrlKDOzYkeqoVSPoBbguow47kaVXqNU4UQ9FabxH1OI6//VMP',
    'tgwDe0QXzGXpXMq6ZFhLyzvYED5hSqR2xSClPSoKC7MlSG4KzbH2qBEHMovEKDeHYPuItWOb',
    'OmPbl/gtsBBfa0o2e6IBa7Q+FO+GMfpfxSV0r7dmTgcYeh01K/9LxpjVjhItqHR74EZa8PLg',
    'iRKySlUX22FAyJhIziH/IfwTRdpJMORcX1PnWPTcylcTQWFkZRAas3G4DtIJCKA+TPvI8+nf',
    '/1t7stf1elT8KFXsr6fw3K1CQRntg7kCDQRT/iGPARAAur2r9TFFGdcr3AGBFC92qPwGUTI3',
    'inFdFc5lFZ6iZ5E/CAZXJvxfnBDmKuiOQVudzgzvTx/EYYUnbGwVVWSwtz3LV56/szHdnwEr',
    'm5zmO6MarQWdiF6io5pLyMYngBegTrJ/dGq3OpRMf/sWhqPeN3WsIQz5rk5HLoiIQb8jO1Io',
    'TbrUX3zXU2eFle90n2NZ73jkMKt+n0efdgRtN5qkUl3KRcEyb5ZWQn72AZo9DKqk2Kk7ehfG',
    'Tw9PO3d6u8NXLEnub8qfaPQTqHfFR3k2hg7A6i8iAzhAxjUueJxnL6RNk+O4KrdQNeHCQ6g5',
    '2zVxKBajISfz36GlwmQg9NT4meARWhDC1YP6EUMv4Y3zEL1OgD3irYR5UeBOnrGj6udO3ZCD',
    '18JRmtcDEkuYGrDC5L/C6Wb1KDjRlv6YMk/Yx16ARfN9yog9/E0+xNqtRpa4SPSn9q/F3qtI',
    'h2cZP+QvT6fbQ9MVnFtY6VqOhhzPVSoOThz8VP63OVGk9qA/JSFdfWl13Hs5mlnvj9219Vuz',
    '4pelY84pgOkO+oyNnJ/e2QlJOeX8rFv0mvBzFDYUMCzA6kANWV5AplXjpNRuW2xIyfmu1v3r',
    'qgVne8JnNPVc3MO3Bc3Qn7qBOuDwNRQIJByJudHlhg1F1AHoXuDZVP4PFDGFrpBzXC/WX3iS',
    'MpjGYF8AEQEAAYkCJQQYAQIADwIbDAUCV72DRgUJBKyvsAAKCRApMBABAAAzRClhEAC7HN7Q',
    'MeMeoxwZe85k5b/JIdNDe34Zs6JR/s7vB3vjGx2xBt8ScLEm6g8/T/3VXVpV0xXP1ufHwl1D',
    'wwUxTEiDv78M6Vwe/vTz0C2zkMOcDwQ3VVGpACnsB0rAAsohXS0eK18Xjy/iNsMOzmDSNmvI',
    'zYaZSkoxjbw7zpaCp0JQS+zUcUrQ4dfVlAKxqXC3xCpePKbzXU+KjZG5MH0rXfc3xvamW3//',
    '0G22UML6tVZHZx2orNWo1T64t3oPfsowWWMjFZ7/yQnt5YrvQEp8gyyOIuSBlIEtGjHkbUAY',
    'v/KsKerhxX0BlfR6c6TAqZHYGauqj0M/sZCIB9cja9PNqNgct5wqpvTIHfculx/aMUPtTJt2',
    'LBKZwZwY4AR5E2UarqhhqqtKQMbnLm9QiilQCMhvragdNdS+zwdpn3UuKwhSq0DZouMwHVuQ',
    'PBcRu5AnI9sOGeWraiQ3Gk0+qyMJY6DOeK8+5bsYOpBnZTUEYi5IxAsN9kwNxpsf7V4IuFXt',
    '/Bovm5B6iGS85sH6pqtbT3skuWDWJvQzee5JZjtARRO+OJl0Ppa+AQQSMrVcZYaq4R2h3eOI',
    '5J6qRTmTZPAFs/HDiE/KTL0CeAyH2bBrRAh2aWd/YhtwY3C6yYr1aqOQozX1M6wxswjnn8Ed',
    'C74BmDbi5TMZG6SLxqVL+hCB63Oz94kCJQQYAQIADwIbDAUCWL1oDwUJBayUfgAKCRApMBAB',
    'AAAzRFfAD/oDkNZ4dWs3jMicA1mMkO8fb0tILtE/4DuSMkEqYsYrZAxFvXbpjbWLb6yhsV/h',
    'imceSkGN3x3Gx8UkLdGgqnNPkdm+eEJiOsF8Jmar+mx3y+tCZ1vrQwRzELKqI7cpn80uzZWu',
    'dUrpLVSHl0ktWfduuGwDEnKBVCagDLTELullaV4eRm+bxey20Y9HP4PYbRu0iIE8YdI76FR5',
    'yh/wnl9nykiY6842LqxZR03Pujz9Sgn4nO8c9TIlSKmbaQalfR5K/R0hY3a5RfIvjTyzNPae',
    'TqWeMizu7m4tpqZax2d0uZr/pGH7G0NqOLeJiRnslTXxXQ8v0uCjuKHgANu24GXMmc8Or6kT',
    'VMelhb51wHEyi3+PLtjisAZGvJjRWeoHbu81nuDL5ZiVY+sAjhEPY7ockS2KLvSgrxiFLK52',
    'LN1UWXUqBETrxG6Qb5Qp6Y0+wBIePIBzdjuHzLIXGcubKJ22erxzrFM7a1ti/QrBEv/XrRkJ',
    'cLZxEqEJCbEDBkhB3DBLfAMSRsoTdCk6JbYUlGvN/U9SZoYu8jiFHnL/0Zbnn0xKFYuzwaWk',
    'aQoxdjIrFcedP9wqHBKc17TbiwKegzZlAu07DamNCSa9urNDZ8ONlXF5tD88reIsePyU3Bnq',
    'XtlnZj8mgwfIek19zoCpQDT/iuK0rSoz707L46gevbwJxokCJQQYAQIADwUCU/4hjwIbDAUJ',
    'A8JnAAAKCRApMBABAAAzRDFUD/9ZFJsK9hFxoPGFfDZAkMnM2j1XiyYM3ydonLGTzgGNfUAn',
    'b8YxZoOPteYMokji4ecg8z5ceGiTR73jdZZR0dvRi3l9b/zjr2y5wBF5jZlgJmbwYt0CGkd9',
    'o6ayuj3SV5hQcsuaMS4zlqUXQ6MCcJcgY8X73SYn1nIjWUMdlWWOlfdKah7zpSavMO0fPY3M',
    'jYrQ4cWV6DxRghTveSpVLT8zd/Tpt6lyEla+BPa7p4m6XiXbpavF9P5KH0p3Zs3vlfYxCL7f',
    'PgX8RjlVMSHplgTnga8DGTrTCuKQMoRhUXyqwF3RQHQVAnFFl0re7ebFkwGmAkt5XtHUkNgv',
    'U9DKqfqWCu094or8dfjxM39s/4E8C51RO8RipBGZhJlJVWjfKdWtkigSIqwCLg8vM1QJBq8d',
    'mPwDOwKcnx6DDrXAKRkrQAFNRGfeK0dH5XxsNRdI94PvRTiHLH6qcvlxDjWB1aWffvKjEcEz',
    'X5i5LiwzaZRtiHwaX7rTB4s38cEDCw69+hH7AzoWZZY/cKhTIxhxXz3PZgXJhRpaSy8eU3d1',
    'rh+tn/KV0AjnMviRCzIjAsjuUzw5F+5J+l1//KjX246Yn+0rWKgYj8sN67QOR7EO9kF7Xwph',
    'zyPPbUy7KiseBJibYV/cgKnpJkF16oofDY+fnuoIq3DcA5mmyR64F/l2yiXAabkCDQRT/iJ+',
    'ARAAsZijXS+AmD6UAuBKobuLofTE79Kkqcxw/yDY1GuKo+xOum21oO3K13OuXqTdQkUZYeh2',
    'ZELtgBnbAKGdEuBjSk9bNPtv5i0+FFAvuFM68vv4jm8s8YSx8rUaXaTRyZv+84yiVW7cpGDs',
    'BqkVk2+2Mb8xyQHc0PWsKpEOoCEMBV0SpzTcsvxlohPefmpL4TkzTs+rVoAq13uXFCuqlPG+',
    'i3gbFv0YxQqPePHHOaEiBfHHeHJCdfUmsyPNBFiCvgU8o5+0Uow+H8hcqJD4cm4gy8OemWEy',
    'h+KwBv6Ap+Cl72chW7+64dkTMrgpXIqYq80wxbEOglBdCCLWDw9BLtYrD7r2nWgQQXM7hnQP',
    'DNhhb6nVSlUODfDEdSZAyTxEg/fT5i5ZnLW4vhwP72DhfHuM6IGpxqHxxTq5/4X8vcgeAf+o',
    'qdQBpfWIH4htpJYap4JaN6EptaNu1Z7V0A+kWSp6BFndjVlnFuAerVTLIPY6ruHAAxrSPVdD',
    'iiAHwZU9RAWJWFJM/NCQD+l8QQ3djutv4s6XmWJCtewneui8f5looTJTaAD97ucki0fNNRDj',
    '0HJIBeM4HqDa0G1gkck29l04r8CRVrzSLG/oZ6wCibthN+a43xDg4JLaXQAImBvacbQ1PErt',
    'IzJaIiN1P2yJZ0pa26pcKsozRIwhJhZ/ZwSM6PsAEQEAAYkERAQYAQIADwIbAgUCV72DiAUJ',
    'BKyu/wIpwV0gBBkBAgAGBQJT/iJ+AAoJEDX/U/iSc289dHYQAIVLcUpdhs33DTWGflT2Xfbm',
    'K+Tussg39L2c6pN0EIqM7+nInHdAz/+F3lcyHAAHUmM9sc6b+419IlYVRrlJ71OAixlvailU',
    '2bPSALNvbYLfh9oTO/co4LxZ01ON9giFg/tKbI1B5CjIVXDezLFoMqN7OS/TfqieSFb6AKuY',
    '1y/aWIZfO7WRKbpfrJOpWU2uk/r6w3EhC36YT6y9tQE7PJbyh1nGqNWftRAB5jS7HEyIyXgl',
    'twnyY5pweqfXqp+eCDDCt8na7T1zZl1Wt8FPNPis9KgRyphRnEJLFB4G5nfvMVl97NnTfITB',
    'yUNdPagqmxJD6GvqN1uWU2cVFpP+mZEjGC37zgq5lbCevm4IjGhJDlrCi/u5LIr+brsF667p',
    '9XqXb3xFiyVasD4S+MyoNpgtPlV/u0teKccWFPBSi23GR+SSdylwZ6mYAYYKILYAsfZKQJYk',
    'Izw8+e1R05myw7PrtPYIn0XYLZo+oV+kOVZT0OjIdNEQsLdWJInxYDCAJMiaJBB7eGFREogr',
    'Q0zCVwK0v+48C58M0ovoAYIrcb82pk/5wjZSomIl0Lu3vz7T72DzHwExQ7qiZCdZjrxfurzI',
    'yBjuhmJP6l0VduBRBxSQ8mGR+QMAtMJq4g7UdUipAT7A7+/dF+5MFUgmrjrFVIPH7I7Faj/n',
    'Chq7VXTpS6asCRApMBABAAAzRA0jD/4o26XlJiaYGAf6DtixejEXpj/PVRe2cDjQkTCnxnX5',
    'ZDDioCVFm0B7KZzcftGimZexA6La37SgDffbfI0dLZGateEeVgJa/zdakfjd8SG0HJxKHXBV',
    'G5x0G/0sWL9uBTtGjUGp44Y8zfey+h77V6KOOO1+rBnYYIgjsD8/P9OsIiHMhlSc7Mh9g4AT',
    'ERdWNIu52SHsWtNyqO7iqgWHFEKGfHPC0lCGtFGDR3/8KrQ0eeZsmVUM2W5wOrbjvaPQAZSM',
    '5YHkTQj5HmlBxZ3kHJ8y0HMjJw+IVheOaEkX4rTcOkt+041IeAIq3bC/kWvKgjQI4NAiUnXU',
    'hJC+yYcJH01fDBbyYDH5ORy9TYZX4WZpIbP+/2WThMsydAkndmeDsb2wi08w53a4hEHnrlBW',
    'hr18+pMtkhh03wgrZR982nacCHnX5EmQzmBJFyl0oYMJjPSKthzuHcDD3ecVWEEtqNwOP6Yv',
    '47MgkFYn0QMYlocyw+mFZml0O5vegS35NrI05iTyuv+yo60aHDGSUvovXQ62gbUcfxLQcBt8',
    '5/6wyOw6bilpPQpiDFuJuNq2W4eUqZjFQR1oxr60eXyh/8RKjP++JwgaRHajHFvLiEvxjUNF',
    'daii1hRGv0OoewDXmLUjZlAfvB0yYsUTYOQfyn3ghn7pLRrsmzulk7kiSM529Sw+iokERAQY',
    'AQIADwIbAgUCWL1oPQUJBayTvQIpwV0gBBkBAgAGBQJT/iJ+AAoJEDX/U/iSc289dHYQAIVL',
    'cUpdhs33DTWGflT2XfbmK+Tussg39L2c6pN0EIqM7+nInHdAz/+F3lcyHAAHUmM9sc6b+419',
    'IlYVRrlJ71OAixlvailU2bPSALNvbYLfh9oTO/co4LxZ01ON9giFg/tKbI1B5CjIVXDezLFo',
    'MqN7OS/TfqieSFb6AKuY1y/aWIZfO7WRKbpfrJOpWU2uk/r6w3EhC36YT6y9tQE7PJbyh1nG',
    'qNWftRAB5jS7HEyIyXgltwnyY5pweqfXqp+eCDDCt8na7T1zZl1Wt8FPNPis9KgRyphRnEJL',
    'FB4G5nfvMVl97NnTfITByUNdPagqmxJD6GvqN1uWU2cVFpP+mZEjGC37zgq5lbCevm4IjGhJ',
    'DlrCi/u5LIr+brsF667p9XqXb3xFiyVasD4S+MyoNpgtPlV/u0teKccWFPBSi23GR+SSdylw',
    'Z6mYAYYKILYAsfZKQJYkIzw8+e1R05myw7PrtPYIn0XYLZo+oV+kOVZT0OjIdNEQsLdWJInx',
    'YDCAJMiaJBB7eGFREogrQ0zCVwK0v+48C58M0ovoAYIrcb82pk/5wjZSomIl0Lu3vz7T72Dz',
    'HwExQ7qiZCdZjrxfurzIyBjuhmJP6l0VduBRBxSQ8mGR+QMAtMJq4g7UdUipAT7A7+/dF+5M',
    'FUgmrjrFVIPH7I7Faj/nChq7VXTpS6asCRApMBABAAAzROhLD/4uw5sm/oLdy1tOOU3kG4zi',
    'Nor/LeGR/GPwm/owtCcUvP9G7frFoGxTMKfMhbpC2Sc5IdlSg+F5Q+GrS7pKisL89ke0NVV3',
    'fX/BB/7fW1CcFpCZt0Ro2Ty6nU1WtLxtdMqOO1hgnFRtWfapgwroWtxUstgKvv33/SY+n6LK',
    'SM2rYTQk0AcY/hNn0n6EdkpcK3uECZVgJhKNr7s4T71ONQKx9TC2aDBD4OmCQIVtZWR8xWVO',
    'TtC4DFPE2elCPxez5gepw8NVr22D2+7dqaMNg3RhOOM28vurUpQ4/6+c0jehJv3+oYbmbdU/',
    'YBhQcQzOTnoe25aRqip9UjRRr2s0MXMHnW4C2NLHsYM+UBSDuZEmiPXQS8P7iZ33ph+hVI2w',
    'EMv7KhP9LeZxewcjHzTQGHS8yaACnFGUHehwey81c+NNnevWOr1UiWZCZcpBON1tSIVwh8WO',
    'NQfClT4LgK+tyN60ITtLn39PBmc8rCRV2dnzbwmj5Jpm+/bxht6KPo27w+9WIl739os5phIL',
    '4Sxznm6emsrgCO/mcX2aP4ejq/UTLh+7C59POfqWHOZL4m3VKKUs/CxuBRXIv5jHVm4n48sP',
    'WBUa7H8RefMrzK9uraqhL6SPyQe/4oOo8i8Z0nJOmVtUI6kZKRtkKyXKYhLCFRAEkBfoLwv5',
    'MJg57DQu/HLSU4kERAQYAQIADwUCU/4ifgIbAgUJA8JnAAIpCRApMBABAAAzRMFdIAQZAQIA',
    'BgUCU/4ifgAKCRA1/1P4knNvPXR2EACFS3FKXYbN9w01hn5U9l325ivk7rLIN/S9nOqTdBCK',
    'jO/pyJx3QM//hd5XMhwAB1JjPbHOm/uNfSJWFUa5Se9TgIsZb2opVNmz0gCzb22C34faEzv3',
    'KOC8WdNTjfYIhYP7SmyNQeQoyFVw3syxaDKjezkv036onkhW+gCrmNcv2liGXzu1kSm6X6yT',
    'qVlNrpP6+sNxIQt+mE+svbUBOzyW8odZxqjVn7UQAeY0uxxMiMl4JbcJ8mOacHqn16qfnggw',
    'wrfJ2u09c2ZdVrfBTzT4rPSoEcqYUZxCSxQeBuZ37zFZfezZ03yEwclDXT2oKpsSQ+hr6jdb',
    'llNnFRaT/pmRIxgt+84KuZWwnr5uCIxoSQ5awov7uSyK/m67Beuu6fV6l298RYslWrA+EvjM',
    'qDaYLT5Vf7tLXinHFhTwUottxkfkkncpcGepmAGGCiC2ALH2SkCWJCM8PPntUdOZssOz67T2',
    'CJ9F2C2aPqFfpDlWU9DoyHTRELC3ViSJ8WAwgCTImiQQe3hhURKIK0NMwlcCtL/uPAufDNKL',
    '6AGCK3G/NqZP+cI2UqJiJdC7t78+0+9g8x8BMUO6omQnWY68X7q8yMgY7oZiT+pdFXbgUQcU',
    'kPJhkfkDALTCauIO1HVIqQE+wO/v3RfuTBVIJq46xVSDx+yOxWo/5woau1V06UumrPiUD/0b',
    'MK0knrkFGbSm0P9E11mQDvUd0S5T4IYai1l82n7nKWfXeF7gC/G4j9S5/ZloaYY0jTHKomOW',
    'uDl0JKf3ILaQi97HqkyE4B6fL0m0Fw1rUjz7ksWPdwbQ4iyJYKx1zwNXYclLpNffZYtAy3tG',
    'jQduZBHBXov9HTVcyaHf53kCHCOuJzuDjYXQHAKGYZ7nXpkGhFXf8KhyOIyNejpqnCggXSxc',
    'Pj5xzXEmC+IKwSI4OCb2df9yIZjQQHd8N4peebuP4OiEWSYTkHMx645Mw5l+Mc/4UcXDTqMr',
    'ftt0tpoRbE59h05g+Bt1EovJ+154syTXAg7lgnjtfGt63CPKx91Vvh0JWIB2kMasJuOMRi4l',
    'h8ziwuAa3i31TYgCWvyxwyDcCt97b8UGRKCH4LL9nR/C58yOS17CtnZX9fz/CwQ3zHJcHeFE',
    '5lsksm6kCODrqOH70gQAMvGU5QOHnzV+U18Efy/d3gpWhjaDAYaHBYunxNNXdUH1cWtsjldb',
    'HjVhQVbnB03zocspBH9npH/8e0uNT99IwhBwlFo4+VkDVRBCZehnHWtbNiiEL0BgnjM9CpZs',
    'a9SckNMyBKkWqxbhqkYKhw8h7x/IfVbI1kudsCmikT0UugznaDo41XlQfXQz477Rp80o9Xya',
    'MDP0g/Hm9QAsR1g4TrOakqSw1g3p+YqPgA==',
    '=Lpo7',
    '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

  it('Parsing armored text with RSA key and ECC subkey in tolerant mode', function(done) {
    openpgp.config.tolerant = true;
    var pubKeys = openpgp.key.readArmored(rsa_ecc_pub);
    expect(pubKeys).to.exist;
    expect(pubKeys.err).to.not.exist;
    expect(pubKeys.keys).to.have.length(1);
    expect(pubKeys.keys[0].primaryKey.getKeyId().toHex()).to.equal('b8e4105cc9dedc77');
    done();
  });

  it('Parsing armored text with RSA key and ECC subkey in non-tolerant mode', function(done) {
    openpgp.config.tolerant = false;
    var pubKeys = openpgp.key.readArmored(rsa_ecc_pub);
    expect(pubKeys).to.exist;
    expect(pubKeys.err).to.exist;
    done();
  });


  var multi_uid_key =
    ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
    'Version: GnuPG v1',
    '',
    'mQENBFbqatUBCADmeA9CjMfzLt3TrplzDxroVisCWO7GRErUXiozULZd5S8p/rHS',
    'kuclUsQzraSuQ+Q7RhpOWdJt9onf5ro0dCC3i+AEWBrS0nyXGAtpgxJmZ618Cwzz',
    'RKrYstce4Hsyg0NS1KCbzCxpfIbyU/GOx4AzsvP3BcbRMvJ6fvrKy6zrhyVq5to3',
    'c6MayKm3cTW0+iDvqbQCMXeKH1MgAj1eOBNrbgQZhTBMhAaIFUb5l9lXUXUmZmSj',
    'r4pjjVZjWudFswXPoVRGpCOU+ahJFZLeIca99bHOl3Hu+fEbVExHdoaVq5W9R/QJ',
    '/0bHQrd+Th8e1qpIP2/ABb6P/7SGUKw6ZUvbABEBAAG0E1Rlc3QgVXNlciA8YUBi',
    'LmNvbT6JATgEEwECACIFAlbqatUCGwMGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheA',
    'AAoJEPhuIdU05lVRgtoH/ioJdP34cHIdSu2Ofsm6FoWc/nk2QEughNn2AyaxZAKO',
    'pWy9o9/+KlVD3SoV5fzl6tCsFz1MqLFBsHSj2wKoQqkU6S9MnrG12HgnirqcjOa0',
    '1uPB0aAqF3ptNScPqcD44bZ4p58TAeU5H7UlrwPUn4gypotAnu+zocNaqe0tKWVo',
    'f+GAZG/FuXJc5OK2J6OmKIABJCuRchXbkyfsXZYE3f+1U9mLse4wHQhGRiSlgqG4',
    'CCSIjeIkqeIvLCj/qGXJGyJ0XeMwMVhajylhEtDmMRlc32Jt8btlTJzcQ/3NPuQd',
    'EryD92vGp/fXwP1/rLtD49o/0UbDeXT4KQphs2DuG/60E1Rlc3QgVXNlciA8YkBj',
    'LmNvbT6JATgEEwECACIFAlbqeUACGwMGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheA',
    'AAoJEPhuIdU05lVRuPkIAK+ieYXEflVHY1bKeptYZ+UfHJhsBdM29WYmuHhAbWe9',
    'mb741n8YXbPENoCSYD4jq7cYOvrduz5QLmXKL57D9rXvu/dWhpLaSjGf4LDrSf+9',
    'bYw0U2BStjPzjnyxZSQDU60KFRIjZPWxF/VqRFp3QIp/r3vjEGuiE6JdzbT4EWwO',
    'rltkMzPYgx7cx63EhjrM3kybylL+wBX3T2JNCzLPfZBsdiWmQcypLgOPLrW/4fxQ',
    'zfAsDyEYlRj7xhVKAc+nMcXo8Hw46AecS8N3htZHM6WeekZYdoJ4DlDeE5RL76xZ',
    'hVEOziY5UnBT/F8dfZoVcyY/5FiSUuL19Cpwoc+dpWm5AQ0EVupq1QEIAMLfhMdk',
    'OoIl1J3J8F89My2u7qwKrw1WLWawBacZH2jsGZrjZlUJEIQpaIyvqHSPSgLJ+Yco',
    'YmCMj/ElNVBKBzaUpfdftW+5/S5OaJVq/j7J1OKMQqXQALgwh8GM/AThO5G4B27c',
    'HZ/+bkbldYJJK0y5ZONEj7gkch7w6cr1+6NCL7jMWIDar3HpchddOproxAMuZa9D',
    '2RjOvl+OMb6JMO5zTFbh37o5fAw3YWbmeX/tp2bD5W4lSUGD/Xwf2zS2r7vwGVZO',
    'C+zx1aaSNllcRvSWkg8zRY5FjL9AOl4l52JFfz8G63EuHrR9dXmsYA9IHunk0UNy',
    '/GGCcIJ6rXKTMCUAEQEAAYkBHwQYAQIACQUCVupq1QIbDAAKCRD4biHVNOZVUUFY',
    'CADkAAtvIiJLoiYyWBx4qdTuHecuBC8On64Ln2PqImowpMb8r5JzMP6aAIBxgfEt',
    'LezjJQbIM6Tcr6nTr1FunbAznrji1s4T6YcrRCS2QLq2j1aDUnLBFPrlAbuRnmZj',
    'o8miZXTSasZw4O8R56jmsbcebivekg0JQMiEsf3TfxmeFQrjSGKGBarn0aklfwDS',
    'JuhA5hs46N+HGvngXVZNAM9grFNxusp2YhC+DVDtcvR3SCVnVRfQojyaUKDEofHw',
    'YD+tjFrH9uxzUEF+0p6he6DJ5KrQuy5Zq4Yc4X2rNvtjsIzww0Byymvo6eRO0Gxk',
    'ljIYQms3pCv1ja6bLlNKpPII',
    '=qxBI',
    '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

  var wrong_key =
    ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
    'Version: OpenPGP.js v0.9.0',
    '',
    'xk0EUlhMvAEB/2MZtCUOAYvyLFjDp3OBMGn3Ev8FwjzyPbIF0JUw+L7y2XR5',
    'RVGvbK88unV3cU/1tOYdNsXI6pSp/Ztjyv7vbBUAEQEAAc0pV2hpdGVvdXQg',
    'VXNlciA8d2hpdGVvdXQudGVzdEB0LW9ubGluZS5kZT7CXAQQAQgAEAUCUlhM',
    'vQkQ9vYOm0LN/0wAAAW4Af9C+kYW1AvNWmivdtr0M0iYCUjM9DNOQH1fcvXq',
    'IiN602mWrkd8jcEzLsW5IUNzVPLhrFIuKyBDTpLnC07Loce1',
    '=6XMW',
    '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

  it('Parsing armored text with two keys', function(done) {
    var pubKeys = openpgp.key.readArmored(twoKeys);
    expect(pubKeys).to.exist;
    expect(pubKeys.err).to.not.exist;
    expect(pubKeys.keys).to.have.length(2);
    expect(pubKeys.keys[0].primaryKey.getKeyId().toHex()).to.equal('4a63613a4d6e4094');
    expect(pubKeys.keys[1].primaryKey.getKeyId().toHex()).to.equal('dbf223e870534df4');
    done();
  });

  it('Testing key ID and fingerprint for V3 and V4 keys', function(done) {
    var pubKeysV4 = openpgp.key.readArmored(twoKeys);
    expect(pubKeysV4).to.exist;
    expect(pubKeysV4.err).to.not.exist;
    expect(pubKeysV4.keys).to.have.length(2);

    var pubKeyV4 = pubKeysV4.keys[0];
    expect(pubKeyV4).to.exist;

    var pubKeysV3 = openpgp.key.readArmored(pub_v3);

    expect(pubKeysV3).to.exist;
    expect(pubKeysV3.err).to.not.exist;
    expect(pubKeysV3.keys).to.have.length(1);

    var pubKeyV3 = pubKeysV3.keys[0];
    expect(pubKeyV3).to.exist;

    expect(pubKeyV4.primaryKey.getKeyId().toHex()).to.equal('4a63613a4d6e4094');
    expect(pubKeyV4.primaryKey.getFingerprint()).to.equal('f470e50dcb1ad5f1e64e08644a63613a4d6e4094');
    expect(pubKeyV3.primaryKey.getKeyId().toHex()).to.equal('e5b7a014a237ba9d');
    expect(pubKeyV3.primaryKey.getFingerprint()).to.equal('a44fcee620436a443bc4913640ab3e49');
    done();
  });

  it('Create new key ID with fromId()', function() {
    var pubKeyV4 = openpgp.key.readArmored(twoKeys).keys[0];
    var keyId = pubKeyV4.primaryKey.getKeyId();
    var newKeyId = keyId.constructor.fromId(keyId.toHex());
    expect(newKeyId.toHex()).to.equal(keyId.toHex());
  });

  it('Testing key method getSubkeyPackets', function(done) {
    var pubKeys = openpgp.key.readArmored(pub_sig_test);

    expect(pubKeys).to.exist;
    expect(pubKeys.err).to.not.exist;
    expect(pubKeys.keys).to.have.length(1);

    var pubKey = pubKeys.keys[0];
    expect(pubKey).to.exist;

    var packetlist = new openpgp.packet.List();

    packetlist.read(openpgp.armor.decode(pub_sig_test).data);

    var subkeys = pubKey.getSubkeyPackets();
    expect(subkeys).to.exist;
    expect(subkeys).to.have.length(2);
    expect(subkeys[0].getKeyId().equals(packetlist[8].getKeyId())).to.be.true;
    expect(subkeys[1].getKeyId().equals(packetlist[11].getKeyId())).to.be.true;
    done();
  });

  it('Verify status of revoked subkey', function(done) {
    var pubKeys = openpgp.key.readArmored(pub_sig_test);
    expect(pubKeys).to.exist;
    expect(pubKeys.err).to.not.exist;
    expect(pubKeys.keys).to.have.length(1);

    var pubKey = pubKeys.keys[0];
    expect(pubKey).to.exist;
    expect(pubKey.subKeys).to.exist;
    expect(pubKey.subKeys).to.have.length(2);

    var status = pubKey.subKeys[0].verify(pubKey.primaryKey);
    expect(status).to.equal(openpgp.enums.keyStatus.revoked);
    done();
  });

  it('Evaluate key flags to find valid encryption key packet', function() {
    var pubKeys = openpgp.key.readArmored(pub_sig_test);
    expect(pubKeys).to.exist;
    expect(pubKeys.err).to.not.exist;
    expect(pubKeys.keys).to.have.length(1);

    var pubKey = pubKeys.keys[0];
    // remove subkeys
    pubKey.subKeys = null;
    // primary key has only key flags for signing
    var keyPacket = pubKey.getEncryptionKeyPacket();
    expect(keyPacket).to.not.exist;
  });

  it('Method getExpirationTime V4 Key', function() {
    var pubKey = openpgp.key.readArmored(twoKeys).keys[1];
    expect(pubKey).to.exist;
    expect(pubKey).to.be.an.instanceof(openpgp.key.Key);
    expect(pubKey.getExpirationTime().toISOString()).to.be.equal('2018-11-26T10:58:29.000Z');
  });

  it('Method getExpirationTime V4 SubKey', function() {
    var pubKey = openpgp.key.readArmored(twoKeys).keys[1];
    expect(pubKey).to.exist;
    expect(pubKey).to.be.an.instanceof(openpgp.key.Key);
    expect(pubKey.subKeys[0].getExpirationTime().toISOString()).to.be.equal('2018-11-26T10:58:29.000Z');
  });

  it('update() - throw error if fingerprints not equal', function() {
    var keys = openpgp.key.readArmored(twoKeys).keys;
    expect(keys[0].update.bind(keys[0], keys[1])).to.throw('Key update method: fingerprints of keys not equal');
  });

  it('update() - merge revocation signature', function() {
    var source = openpgp.key.readArmored(pub_revoked).keys[0];
    var dest = openpgp.key.readArmored(pub_revoked).keys[0];
    expect(source.revocationSignature).to.exist;
    dest.revocationSignature = null;
    dest.update(source);
    expect(dest.revocationSignature).to.exist.and.be.an.instanceof(openpgp.packet.Signature);
  });

  it('update() - merge user', function() {
    var source = openpgp.key.readArmored(pub_sig_test).keys[0];
    var dest = openpgp.key.readArmored(pub_sig_test).keys[0];
    expect(source.users[1]).to.exist;
    dest.users.pop();
    dest.update(source);
    expect(dest.users[1]).to.exist;
    expect(dest.users[1].userId).to.equal(source.users[1].userId);
  });

  it('update() - merge user - other and revocation certification', function() {
    var source = openpgp.key.readArmored(pub_sig_test).keys[0];
    var dest = openpgp.key.readArmored(pub_sig_test).keys[0];
    expect(source.users[1].otherCertifications).to.exist;
    expect(source.users[1].revocationCertifications).to.exist;
    dest.users[1].otherCertifications = null;
    dest.users[1].revocationCertifications.pop();
    dest.update(source);
    expect(dest.users[1].otherCertifications).to.exist.and.to.have.length(1);
    expect(dest.users[1].otherCertifications[0].signature).to.equal(source.users[1].otherCertifications[0].signature);
    expect(dest.users[1].revocationCertifications).to.exist.and.to.have.length(2);
    expect(dest.users[1].revocationCertifications[1].signature).to.equal(source.users[1].revocationCertifications[1].signature);
  });

  it('update() - merge subkey', function() {
    var source = openpgp.key.readArmored(pub_sig_test).keys[0];
    var dest = openpgp.key.readArmored(pub_sig_test).keys[0];
    expect(source.subKeys[1]).to.exist;
    dest.subKeys.pop();
    dest.update(source);
    expect(dest.subKeys[1]).to.exist;
    expect(dest.subKeys[1].subKey.getKeyId().toHex()).to.equal(source.subKeys[1].subKey.getKeyId().toHex());
  });

  it('update() - merge subkey - revocation signature', function() {
    var source = openpgp.key.readArmored(pub_sig_test).keys[0];
    var dest = openpgp.key.readArmored(pub_sig_test).keys[0];
    expect(source.subKeys[0].revocationSignature).to.exist;
    dest.subKeys[0].revocationSignature = null;
    dest.update(source);
    expect(dest.subKeys[0].revocationSignature).to.exist;
    expect(dest.subKeys[0].revocationSignature.signature).to.equal(dest.subKeys[0].revocationSignature.signature);
  });

  it('update() - merge private key into public key', function() {
    var source = openpgp.key.readArmored(priv_key_rsa).keys[0];
    var dest = openpgp.key.readArmored(twoKeys).keys[0];
    expect(dest.isPublic()).to.be.true;
    dest.update(source);
    expect(dest.isPrivate()).to.be.true;
    expect(source.verifyPrimaryKey()).to.equal(dest.verifyPrimaryKey());
    expect(source.users[0].verify(source.primaryKey)).to.equal(dest.users[0].verify(dest.primaryKey));
    expect(source.subKeys[0].verify(source.primaryKey)).to.equal(dest.subKeys[0].verify(dest.primaryKey));
  });

  it('update() - merge private key into public key - no subkeys', function() {
    var source = openpgp.key.readArmored(priv_key_rsa).keys[0];
    var dest = openpgp.key.readArmored(twoKeys).keys[0];
    source.subKeys = null;
    dest.subKeys = null;
    expect(dest.isPublic()).to.be.true;
    dest.update(source);
    expect(dest.isPrivate()).to.be.true;
    expect(source.verifyPrimaryKey()).to.equal(dest.verifyPrimaryKey());
    expect(source.users[0].verify(source.primaryKey)).to.equal(dest.users[0].verify(dest.primaryKey));
  });

  it('update() - merge private key into public key - mismatch throws error', function() {
    var source = openpgp.key.readArmored(priv_key_rsa).keys[0];
    var dest = openpgp.key.readArmored(twoKeys).keys[0];
    source.subKeys = null;
    expect(dest.subKeys).to.exist;
    expect(dest.isPublic()).to.be.true;
    expect(dest.update.bind(dest, source)).to.throw('Cannot update public key with private key if subkey mismatch');
  });

  it('update() - merge subkey binding signatures', function() {
    var source = openpgp.key.readArmored(pgp_desktop_pub).keys[0];
    var dest = openpgp.key.readArmored(pgp_desktop_priv).keys[0];
    expect(source.subKeys[0].bindingSignatures[0]).to.exist;
    expect(source.subKeys[0].verify(source.primaryKey)).to.equal(openpgp.enums.keyStatus.valid);
    expect(dest.subKeys[0].bindingSignatures[0]).to.not.exist;
    dest.update(source);
    expect(dest.subKeys[0].bindingSignatures[0]).to.exist;
    expect(dest.subKeys[0].verify(source.primaryKey)).to.equal(openpgp.enums.keyStatus.valid);
  });

  it('getPreferredSymAlgo() - one key - AES256', function() {
    var key1 = openpgp.key.readArmored(twoKeys).keys[0];
    var prefAlgo = openpgp.key.getPreferredSymAlgo([key1]);
    expect(prefAlgo).to.equal(openpgp.enums.symmetric.aes256);
  });

  it('getPreferredSymAlgo() - two key - AES128', function() {
    var keys = openpgp.key.readArmored(twoKeys).keys;
    var key1 = keys[0];
    var key2 = keys[1];
    key2.getPrimaryUser().selfCertificate.preferredSymmetricAlgorithms = [6,7,3];
    var prefAlgo = openpgp.key.getPreferredSymAlgo([key1, key2]);
    expect(prefAlgo).to.equal(openpgp.enums.symmetric.aes128);
  });

  it('getPreferredSymAlgo() - two key - one without pref', function() {
    var keys = openpgp.key.readArmored(twoKeys).keys;
    var key1 = keys[0];
    var key2 = keys[1];
    key2.getPrimaryUser().selfCertificate.preferredSymmetricAlgorithms = null;
    var prefAlgo = openpgp.key.getPreferredSymAlgo([key1, key2]);
    expect(prefAlgo).to.equal(openpgp.config.encryption_cipher);
  });

  it('Preferences of generated key', function(done) {
    var testPref = function(key) {
      // key flags
      var keyFlags = openpgp.enums.keyFlags;
      expect(key.users[0].selfCertifications[0].keyFlags[0] & keyFlags.certify_keys).to.equal(keyFlags.certify_keys);
      expect(key.users[0].selfCertifications[0].keyFlags[0] & keyFlags.sign_data).to.equal(keyFlags.sign_data);
      expect(key.subKeys[0].bindingSignatures[0].keyFlags[0] & keyFlags.encrypt_communication).to.equal(keyFlags.encrypt_communication);
      expect(key.subKeys[0].bindingSignatures[0].keyFlags[0] & keyFlags.encrypt_storage).to.equal(keyFlags.encrypt_storage);
      var sym = openpgp.enums.symmetric;
      expect(key.users[0].selfCertifications[0].preferredSymmetricAlgorithms).to.eql([sym.aes256, sym.aes128, sym.aes192, sym.cast5, sym.tripledes]);
      var hash = openpgp.enums.hash;
      expect(key.users[0].selfCertifications[0].preferredHashAlgorithms).to.eql([hash.sha256, hash.sha512, hash.sha1]);
      var compr = openpgp.enums.compression;
      expect(key.users[0].selfCertifications[0].preferredCompressionAlgorithms).to.eql([compr.zlib, compr.zip]);
      expect(key.users[0].selfCertifications[0].features).to.eql(openpgp.config.integrity_protect ? [1] : null); // modification detection
    };
    var opt = {numBits: 512, userIds: 'test <a@b.com>', passphrase: 'hello'};
    if (openpgp.util.getWebCryptoAll()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys
    openpgp.generateKey(opt).then(function(key) {
      testPref(key.key);
      testPref(openpgp.key.readArmored(key.publicKeyArmored).keys[0]);
      done();
    });
  });

  it('User attribute packet read & write', function() {
    var key = openpgp.key.readArmored(user_attr_key).keys[0];
    var key2 = openpgp.key.readArmored(key.armor()).keys[0];
    expect(key.users[1].userAttribute).eql(key2.users[1].userAttribute);
  });

  it('getPrimaryUser()', function() {
    var key = openpgp.key.readArmored(pub_sig_test).keys[0];
    var primUser = key.getPrimaryUser();
    expect(primUser).to.exist;
    expect(primUser.user.userId.userid).to.equal('Signature Test <signature@test.com>');
    expect(primUser.selfCertificate).to.be.an.instanceof(openpgp.packet.Signature);
  });

  it('Generated key is not unlocked by default', function(done) {
    var opt = {numBits: 512, userIds: 'test <a@b.com>', passphrase: '123'};
    if (openpgp.util.getWebCryptoAll()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys
    var key;
    openpgp.generateKey(opt).then(function(newKey) {
      key = newKey;
      return openpgp.message.fromText('hello').encrypt([key.key]);
    }).then(function(msg) {
      return msg.decrypt(key.key);
    }).catch(function(err) {
      expect(err.message).to.equal('Private key is not decrypted.');
      done();
    });
  });

  it('Generate key - single userid', function(done) {
    var userId = 'test <a@b.com>';
    var opt = {numBits: 512, userIds: userId, passphrase: '123'};
    if (openpgp.util.getWebCryptoAll()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys
    openpgp.generateKey(opt).then(function(key) {
      key = key.key;
      expect(key.users.length).to.equal(1);
      expect(key.users[0].userId.userid).to.equal(userId);
      done();
    }).catch(done);
  });

  it('Generate key - multi userid', function(done) {
    var userId1 = 'test <a@b.com>';
    var userId2 = 'test <b@c.com>';
    var opt = {numBits: 512, userIds: [userId1, userId2], passphrase: '123'};
    if (openpgp.util.getWebCryptoAll()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys
    openpgp.generateKey(opt).then(function(key) {
      key = key.key;
      expect(key.users.length).to.equal(2);
      expect(key.users[0].userId.userid).to.equal(userId1);
      expect(key.users[0].selfCertifications[0].isPrimaryUserID).to.be.true;
      expect(key.users[1].userId.userid).to.equal(userId2);
      expect(key.users[1].selfCertifications[0].isPrimaryUserID).to.be.null;
      done();
    }).catch(done);
  });

  it('Encrypt key with new passphrase', function(done) {
    var userId = 'test <a@b.com>';
    var opt = {numBits: 512, userIds: userId, passphrase: 'passphrase'};
    if (openpgp.util.getWebCryptoAll()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys
    openpgp.generateKey(opt).then(function(key) {
      key = key.key;
      var armor1 = key.armor();
      var armor2 = key.armor();
      expect(armor1).to.equal(armor2);
      expect(key.decrypt('passphrase')).to.be.true;
      expect(key.primaryKey.isDecrypted).to.be.true;
      key.encrypt('new_passphrase');
      expect(key.primaryKey.isDecrypted).to.be.false;
      expect(key.decrypt('passphrase')).to.be.false;
      expect(key.primaryKey.isDecrypted).to.be.false;
      expect(key.decrypt('new_passphrase')).to.be.true;
      expect(key.primaryKey.isDecrypted).to.be.true;
      var armor3 = key.armor();
      expect(armor3).to.not.equal(armor1);
      done();
    }).catch(done);
  });
  it('Generate key - ensure keyExpirationTime works', function(done) {
    var expect_delta = 365 * 24 * 60 * 60;
    var userId = 'test <a@b.com>';
    var opt = {numBits: 512, userIds: userId, passphrase: '123', keyExpirationTime: expect_delta};
    if (openpgp.util.getWebCryptoAll()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys
    openpgp.generateKey(opt).then(function(key) {
      key = key.key;

      var expiration = key.getExpirationTime();
      expect(expiration).to.exist;

      var actual_delta = (new Date(expiration) - new Date()) / 1000;
      expect(Math.abs(actual_delta - expect_delta)).to.be.below(60);

      done();
    }).catch(done);
  });

  it('Sign and verify key - primary user', function(done) {
    var key = openpgp.key.readArmored(pub_sig_test).keys[0];
    var privateKey = openpgp.key.readArmored(priv_key_rsa).keys[0];
    privateKey.decrypt('hello world');
    key = key.signPrimaryUser([privateKey]);
    var signatures = key.verifyPrimaryUser([privateKey]);
    expect(signatures.length).to.equal(2);
    expect(signatures[0].keyid.toHex()).to.equal(key.getSigningKeyPacket().getKeyId().toHex());
    expect(signatures[0].valid).to.be.null;
    expect(signatures[1].keyid.toHex()).to.equal(privateKey.getSigningKeyPacket().getKeyId().toHex());
    expect(signatures[1].valid).to.be.true;
    done();
  });

  it('Sign key and verify with wrong key - primary user', function(done) {
    var key = openpgp.key.readArmored(pub_sig_test).keys[0];
    var privateKey = openpgp.key.readArmored(priv_key_rsa).keys[0];
    var wrongKey = openpgp.key.readArmored(wrong_key).keys[0];
    privateKey.decrypt('hello world');
    key = key.signPrimaryUser([privateKey]);
    var signatures = key.verifyPrimaryUser([wrongKey]);
    expect(signatures.length).to.equal(2);
    expect(signatures[0].keyid.toHex()).to.equal(key.getSigningKeyPacket().getKeyId().toHex());
    expect(signatures[0].valid).to.be.null;
    expect(signatures[1].keyid.toHex()).to.equal(privateKey.getSigningKeyPacket().getKeyId().toHex());
    expect(signatures[1].valid).to.be.null;
    done();
  });

  it('Sign and verify key - all users', function(done) {
    var key = openpgp.key.readArmored(multi_uid_key).keys[0];
    var privateKey = openpgp.key.readArmored(priv_key_rsa).keys[0];
    privateKey.decrypt('hello world');
    key = key.signAllUsers([privateKey]);
    var signatures = key.verifyAllUsers([privateKey]);
    expect(signatures.length).to.equal(4);
    expect(signatures[0].userid).to.equal(key.users[0].userId.userid);
    expect(signatures[0].keyid.toHex()).to.equal(key.getSigningKeyPacket().getKeyId().toHex());
    expect(signatures[0].valid).to.be.null;
    expect(signatures[1].userid).to.equal(key.users[0].userId.userid);
    expect(signatures[1].keyid.toHex()).to.equal(privateKey.getSigningKeyPacket().getKeyId().toHex());
    expect(signatures[1].valid).to.be.true;
    expect(signatures[2].userid).to.equal(key.users[1].userId.userid);
    expect(signatures[2].keyid.toHex()).to.equal(key.getSigningKeyPacket().getKeyId().toHex());
    expect(signatures[2].valid).to.be.null;
    expect(signatures[3].userid).to.equal(key.users[1].userId.userid);
    expect(signatures[3].keyid.toHex()).to.equal(privateKey.getSigningKeyPacket().getKeyId().toHex());
    expect(signatures[3].valid).to.be.true;
    done();
  });

  it('Sign key and verify with wrong key - all users', function(done) {
    var key = openpgp.key.readArmored(multi_uid_key).keys[0];
    var privateKey = openpgp.key.readArmored(priv_key_rsa).keys[0];
    var wrongKey = openpgp.key.readArmored(wrong_key).keys[0];
    privateKey.decrypt('hello world');
    key = key.signAllUsers([privateKey]);
    var signatures = key.verifyAllUsers([wrongKey]);
    expect(signatures.length).to.equal(4);
    expect(signatures[0].userid).to.equal(key.users[0].userId.userid);
    expect(signatures[0].keyid.toHex()).to.equal(key.getSigningKeyPacket().getKeyId().toHex());
    expect(signatures[0].valid).to.be.null;
    expect(signatures[1].userid).to.equal(key.users[0].userId.userid);
    expect(signatures[1].keyid.toHex()).to.equal(privateKey.getSigningKeyPacket().getKeyId().toHex());
    expect(signatures[1].valid).to.be.null;
    expect(signatures[2].userid).to.equal(key.users[1].userId.userid);
    expect(signatures[2].keyid.toHex()).to.equal(key.getSigningKeyPacket().getKeyId().toHex());
    expect(signatures[2].valid).to.be.null;
    expect(signatures[3].userid).to.equal(key.users[1].userId.userid);
    expect(signatures[3].keyid.toHex()).to.equal(privateKey.getSigningKeyPacket().getKeyId().toHex());
    expect(signatures[3].valid).to.be.null;
    done();
  });
  it('Reformat key without passphrase', function(done) {
    var userId1 = 'test1 <a@b.com>';
    var userId2 = 'test2 <b@a.com>';
    var opt = {numBits: 512, userIds: userId1};
    if (openpgp.util.getWebCryptoAll()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys
    openpgp.generateKey(opt).then(function(key) {
      key = key.key
      expect(key.users.length).to.equal(1);
      expect(key.users[0].userId.userid).to.equal(userId1);
      expect(key.primaryKey.isDecrypted).to.be.true;
      opt.privateKey = key;
      opt.userIds = userId2;
      openpgp.reformatKey(opt).then(function(newKey) {
        newKey = newKey.key
        expect(newKey.users.length).to.equal(1);
        expect(newKey.users[0].userId.userid).to.equal(userId2);
        expect(newKey.primaryKey.isDecrypted).to.be.true;
        done();
      }).catch(done);
    }).catch(done);
  });
  it('Reformat and encrypt key', function(done) {
    var userId1 = 'test1 <a@b.com>';
    var userId2 = 'test2 <b@c.com>';
    var userId3 = 'test3 <c@d.com>';
    var opt = {numBits: 512, userIds: userId1};
    if (openpgp.util.getWebCryptoAll()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys
    openpgp.generateKey(opt).then(function(key) {
      key = key.key
      opt.privateKey = key;
      opt.userIds = [userId2, userId3];
      opt.passphrase = '123';
      openpgp.reformatKey(opt).then(function(newKey) {
        newKey = newKey.key
        expect(newKey.users.length).to.equal(2);
        expect(newKey.users[0].userId.userid).to.equal(userId2);
        expect(newKey.primaryKey.isDecrypted).to.be.false;
        newKey.decrypt('123');
        expect(newKey.primaryKey.isDecrypted).to.be.true;
        done();
      }).catch(done);
    }).catch(done);
  });
  it('Sign and encrypt with reformatted key', function(done) {
    var userId1 = 'test1 <a@b.com>';
    var userId2 = 'test2 <b@a.com>';
    var opt = {numBits: 512, userIds: userId1};
    if (openpgp.util.getWebCryptoAll()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys
    openpgp.generateKey(opt).then(function(key) {
      key = key.key
      opt.privateKey = key;
      opt.userIds = userId2;
      openpgp.reformatKey(opt).then(function(newKey) {
        newKey = newKey.key
        openpgp.encrypt({data: 'hello', publicKeys: newKey.toPublic(), privateKeys: newKey, armor: true}).then(function(encrypted) {
          openpgp.decrypt({message: openpgp.message.readArmored(encrypted.data), privateKey: newKey, publicKeys: newKey.toPublic()}).then(function(decrypted) {
            expect(decrypted.data).to.equal('hello');
            expect(decrypted.signatures[0].valid).to.be.true;
            done();
          }).catch(done);
        }).catch(done);
      }).catch(done);
    }).catch(done);
  });

  it('Find a valid subkey binding signature among many invalid ones', function(done) {
    var k = openpgp.key.readArmored(valid_binding_sig_among_many_expired_sigs_pub).keys[0];
    expect(k.getEncryptionKeyPacket()).to.not.be.null;
    done();
  });
});

