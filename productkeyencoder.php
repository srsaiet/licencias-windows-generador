<?php
	/**
	 * ProductKeyEncoder.php — Port fiel del algoritmo 5x5 (2009) con GMP
	 * Requiere: PHP con extensión GMP habilitada.
	 */

	if (!function_exists('gmp_init')) {
		throw new RuntimeException("Se requiere la extensión GMP en PHP.");
	}

	/* ========================= Utilidades GMP ========================= */

	function pow2(int $n): GMP { return gmp_pow(gmp_init(2, 10), $n); }
	function gmp_shl(GMP $x, int $n): GMP { return gmp_mul($x, pow2($n)); }
	function gmp_shr(GMP $x, int $n): GMP { return gmp_div_q($x, pow2($n)); }
	function gmp_and_u(GMP $x, string $hexMask): GMP { return gmp_and($x, gmp_init($hexMask, 16)); }
	function gmp_or_u(GMP $a, GMP $b): GMP { return gmp_or($a, $b); }
	function gmp_to_hex(GMP $x, int $pad = 0): string {
		$h = gmp_strval($x, 16);
		if ($pad > 0) $h = str_pad($h, $pad, '0', STR_PAD_LEFT);
		return $h;
	}

	/* ========================= CRC32 MPEG-2 ========================= */

	function crc_table(): array {
		$tab = [];
		for ($i = 0; $i < 256; $i++) {
			$k = ($i << 24) & 0xFFFFFFFF;
			for ($bit = 0; $bit < 8; $bit++) {
				if ($k & 0x80000000) {
					$k = (($k << 1) ^ 0x04C11DB7) & 0xFFFFFFFF;
				} else {
					$k = ($k << 1) & 0xFFFFFFFF;
				}
			}
			$tab[$i] = $k & 0xFFFFFFFF;
		}
		return $tab;
	}
	$CRC32_TABLE = crc_table();

	/* ========================= Conversión de bytes ========================= */

	function gmp_to_le_bytes(GMP $x, int $len): string {
		$bytes = [];
		$n = gmp_init($x, 10);
		for ($i = 0; $i < $len; $i++) {
			$b = gmp_intval(gmp_mod($n, 256));
			$bytes[] = chr($b);
			$n = gmp_div_q($n, 256);
		}
		return implode('', $bytes);
	}

	/* ========================= Decoder ========================= */

	final class ProductKeyDecoder {
		public const ALPHABET = 'BCDFGHJKMPQRTVWXY2346789'; // N omitida

		public string $key_5x5;
		public GMP $key;
		public GMP $group;
		public GMP $serial;
		public GMP $security;
		public GMP $checksum;
		public GMP $upgrade;
		public GMP $extra;

		public function __construct(string $key) {
			$this->key_5x5 = $key;
			$this->key     = self::decode_5x5($key, self::ALPHABET);

			$this->group    = gmp_and_u($this->key, '000000000000000000000000000fffff');
			$this->serial   = gmp_shr(gmp_and_u($this->key, '00000000000000000003fffffff00000'), 20);
			$this->security = gmp_shr(gmp_and_u($this->key, '0000007ffffffffffffc000000000000'), 50);
			$this->checksum = gmp_shr(gmp_and_u($this->key, '0001ff80000000000000000000000000'), 103);
			$this->upgrade  = gmp_shr(gmp_and_u($this->key, '00020000000000000000000000000000'), 113);
			$this->extra    = gmp_shr(gmp_and_u($this->key, '00040000000000000000000000000000'), 114);
		}

		public function __toString(): string { return $this->key_5x5; }

		public static function decode_5x5(string $key, string $alphabet): GMP {
			$key = str_replace('-', '', $key);
			$posN = strpos($key, 'N');
			$dec = [$posN];
			$keyNoN = str_replace('N', '', $key);
			for ($i = 0; $i < strlen($keyNoN); $i++) {
				$l = $keyNoN[$i];
				$dec[] = strpos($alphabet, $l);
			}
			$acc = gmp_init(0, 10);
			foreach ($dec as $x) {
				$acc = gmp_add(gmp_mul($acc, 24), $x);
			}
			return $acc;
		}
	}

	/* ========================= Encoder ========================= */

	final class ProductKeyEncoder {
		public const ALPHABET = 'BCDFGHJKMPQRTVWXY2346789'; // N omitida
		// Límites: group, serial, security, checksum, upgrade, extra
		private const BOUNDS = ['0xfffff','0x3fffffff','0x1fffffffffffff','0x3ff','0x1','0x1'];

		public GMP $key;
		public string $key_5x5;
		public GMP $checksum;

		public function __construct(int|string $group, int|string $serial, int|string $security, int|string $upgrade, int|string $checksum = '0x400', int|string $extra = 0) {
			$g  = gmp_init($group, 0);
			$s  = gmp_init($serial, 0);
			$sec= gmp_init($security, 0);
			$up = gmp_init($upgrade, 0);
			$cs = gmp_init($checksum, 0);
			$ex = gmp_init($extra, 0);

			// Bound checking idéntico al Python
			$boundsOk = [
				gmp_cmp($g,  gmp_init(self::BOUNDS[0], 0)) <= 0,
				gmp_cmp($s,  gmp_init(self::BOUNDS[1], 0)) <= 0,
				gmp_cmp($sec,gmp_init(self::BOUNDS[2], 0)) <= 0,
				gmp_cmp(gmp_sub($cs, 1), gmp_init(self::BOUNDS[3], 0)) <= 0,
				gmp_cmp($up, gmp_init(self::BOUNDS[4], 0)) <= 0,
				gmp_cmp($ex, gmp_init(self::BOUNDS[5], 0)) <= 0,
			];
			if (in_array(false, $boundsOk, true)) {
				throw new RuntimeException('Key parameter(s) not within bounds');
			}

			// Construcción del entero clave
			$key = gmp_init(0, 10);
			if (gmp_cmp($ex, 0) !== 0) {
				$key = gmp_or_u($key, gmp_shl($ex, 114));
			}
			$key = gmp_or_u($key, gmp_shl($up, 113));
			$key = gmp_or_u($key, gmp_shl($sec, 50));
			$key = gmp_or_u($key, gmp_shl($s, 20));
			$key = gmp_or_u($key, $g);

			// Checksum automático si es 0x400
			if (gmp_cmp($cs, gmp_init('0x400', 0)) === 0) {
				$cs = self::checksum_key(gmp_to_le_bytes($key, 16));
			}
			$this->checksum = $cs;
			$key = gmp_or_u($key, gmp_shl($cs, 103));

			// Restricción de "extra" para encodabilidad
			if (gmp_cmp($ex, 0) !== 0) {
				$limit = gmp_shl(gmp_init('0x62A32B15518', 0), 72);
				if (gmp_cmp($key, $limit) > 0) {
					throw new RuntimeException('Extra parameter unencodable');
				}
			}

			$this->key = $key;
			$this->key_5x5 = self::to_5x5($key);
		}

		public function __toString(): string { return $this->key_5x5; }

		/**
		 * Convierte el entero clave a formato 5x5 con inserción de 'N' y guiones.
		 */
		public static function to_5x5(GMP $key): string {
			// encode(): 25 bytes LE, cada byte = (key % 24), luego key //= 24
			$num = gmp_init(0, 10);
			$k   = gmp_init($key, 10);
			for ($i = 0; $i < 25; $i++) {
				$num = gmp_shl($num, 8);
				$mod = gmp_intval(gmp_mod($k, 24));
				$num = gmp_or_u($num, gmp_init($mod, 10));
				$k   = gmp_div_q($k, 24);
			}
			$bytes = gmp_to_le_bytes($num, 25);

			// Construye el 5x5: bytes[1:] mapeados al alfabeto, inserta 'N' en posición bytes[0]
			$alpha = ProductKeyDecoder::ALPHABET;
			$key_5x5 = [];
			for ($i = 1; $i < 25; $i++) {
				$idx = ord($bytes[$i]); // 0..23
				$key_5x5[] = $alpha[$idx];
			}
			$posN = ord($bytes[0]); // 0..24
			array_splice($key_5x5, $posN, 0, ['N']);

			// Guiones en 5, 11, 17, 23
			array_splice($key_5x5, 5, 0, ['-']);
			array_splice($key_5x5, 11, 0, ['-']);
			array_splice($key_5x5, 17, 0, ['-']);
			array_splice($key_5x5, 23, 0, ['-']);

			return implode('', $key_5x5);
		}

		/**
		 * Calcula el CRC truncado a 10 bits sobre los 16 bytes LE del entero clave.
		 * Polinomio MPEG-2 con tabla precomputada.
		 */
		public static function checksum_key(string $keyBytes): GMP {
			global $CRC32_TABLE;
			$crc = 0xFFFFFFFF;
			$len = strlen($keyBytes);
			for ($i = 0; $i < $len; $i++) {
				$byte = ord($keyBytes[$i]);
				$idx = (($crc >> 24) ^ $byte) & 0xFF;
				$crc = (($crc << 8) & 0xFFFFFFFF) ^ $CRC32_TABLE[$idx];
			}
			$crc = (~$crc) & 0x3FF; // 10 bits
			return gmp_init($crc, 10);
		}
	}
?>