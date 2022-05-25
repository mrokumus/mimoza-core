<?php

namespace Mrt\MimozaCore;

use Carbon\Carbon;
use Carbon\CarbonPeriod;
use DateTime;
use Exception;

class Functions
{
	/**
	 * dili olan formları post etmek istediğimizde bunu gönderirsek sistem kendisi dili ekleyip post edecektir
	 * @var
	 */
	public $formLang;

	/**
	 * Y-m-d H:i:s formatindaki tarihi 12 Şubat,2018 formatına döndürür
	 *
	 * @param $date
	 * @return string|null
	 * @throws Exception
	 */
	public function dateLong($date): ?string
	{
		if (empty($date)) {
			return null;
		}
		$date = new DateTime($date);
		return $date->format("d") . " " . Constants::months[$_SESSION["lang"]]["long"][$date->format("m")] . ", " . $date->format("Y");
	}

	/**
	 * Y-m-d H:i:s formatindaki tarihi 12 Şub,2018 formatına döndürür
	 *
	 * @param $date
	 * @return string|null
	 * @throws Exception
	 */
	public function dateShort($date): ?string
	{
		if (empty($date)) {
			return null;
		}

		$date = new DateTime($date);
		return $date->format("d") . " " . Constants::months[$_SESSION["lang"]]["short"][$date->format("m")] . ", " . $date->format("Y");
	}

	/**
	 * Y-m-d H:i:s formatindaki tarihi 12 Şubat,2018 formatına döndürür
	 * @param $date
	 * @return string
	 * @throws Exception
	 */
	public function dateLongWithTime($date): string
	{
		$date = new DateTime($date);
		return $date->format("d") . " " . Constants::months[$_SESSION["lang"]]["long"][$date->format("m")] . ", " . $date->format("Y") . " " . $date->format("H") . ":" . $date->format("i");
	}

	/**
	 * @param $url
	 */
	public function redirect($url): void
	{
		if ($url) {
			if (!headers_sent()) {
				header("Location:" . $url);
			} else {
				echo '<script>location.href="' . $url . '";</script>';
			}
		}
		exit;
	}

	/**
	 * @param $text
	 * @return string|null
	 */
	public function cleaner($text): ?string
	{
		if (!empty($text)) {
			$array = array('insert', 'update', 'union', '<script', 'alert', 'select', '*');
			$text = str_replace($array, '', $text);
			return htmlspecialchars(stripslashes(strip_tags(trim($text))));
		}
		return NULL;
	}

	/**
	 * @param $text
	 * @return string|null
	 */
	public function cleanerTextarea($text): ?string
	{
		if (!empty($text)) {
			return trim(str_replace(['insert', 'update', 'union', 'select', '*', '<script'], ['', '', '', '', '', ''], $text));
		}
		return NULL;
	}

	/**
	 * @param $mail
	 * @return bool
	 */
	public function isEmail($mail): bool
	{
		if (filter_var($mail, FILTER_VALIDATE_EMAIL)) {
			return true;
		}

		return false;
	}

	/**
	 * @param $url
	 * @return bool
	 */
	public function isUrl($url): bool
	{
		if (filter_var($this->cleaner($url), FILTER_VALIDATE_URL)) {
			return true;
		}
		return false;
	}

	/**
	 * It's return csrf token input for forms
	 * @return string
	 * @throws Exception
	 */
	public function csrfToken(): string
	{
		if (!isset($_SESSION['token'])) {
			$_SESSION['token'] = base64_encode($this->generateRandomString(32));
		}
		return '<input type="hidden" name="token" id="token" value="' . $_SESSION['token'] . '">';
	}

	/**
	 * It's return csrf token
	 *
	 * @throws Exception
	 */
	public function getCsrfToken(): string
	{
		if (!isset($_SESSION['token'])) {
			$_SESSION['token'] = base64_encode($this->generateRandomString(32));
		}
		return $_SESSION['token'];
	}

	/**
	 * @param string $str
	 * @param int $limit
	 * @return string
	 */
	public function shorten(string $str, int $limit = 10): string
	{
		$str = strip_tags(htmlspecialchars_decode(html_entity_decode($str), ENT_QUOTES));
		$length = strlen($str);
		if ($length > $limit) {
			$str = mb_substr($str, 0, $limit, 'UTF-8');
		}
		return $str;
	}

	/**
	 * It's make permalink
	 *
	 * @param string $text
	 * @param string $divider
	 * @return string
	 */
	public function permalink(string $text, string $divider = '-'): string
	{
		$text = strtolower(preg_replace('~-+~', $divider, trim(preg_replace('~[^-\w]+~', '', iconv('utf-8', 'us-ascii//TRANSLIT', preg_replace('~[^\pL\d]+~u', $divider, $text))), $divider)));
		if ($text === '') {
			return 'n-a';
		}
		return $text;
	}

	/**
	 * It's return ip address
	 * @return string
	 */
	public function getIpAddress(): string
	{
		if (getenv("HTTP_CLIENT_IP")) {
			$ip = getenv("HTTP_CLIENT_IP");
		} elseif (getenv("HTTP_X_FORWARDED_FOR")) {
			$ip = getenv("HTTP_X_FORWARDED_FOR");
			if (strpos($ip, ',') !== false) {
				$tmp = explode(',', $ip);
				$ip = trim($tmp[0]);
			}
		} else {
			$ip = getenv("REMOTE_ADDR");
		}
		return $ip;
	}

	/**
	 * It's return integer as a size units ( GB, MB , KB ...)
	 * @param int|string $bytes
	 * @return string
	 */
	public function formatSizeUnits($bytes): string
	{
		if (!is_numeric($bytes)) {
			return 'NAN';
		}
		if ($bytes >= 1208925819614629174706176) {
			$bytes = number_format($bytes / 1208925819614629174706176, 2) . ' YB';
		} // Yotta Bytes
		elseif ($bytes >= 1180591620717411303424) {
			$bytes = number_format($bytes / 1180591620717411303424, 2) . ' ZB';
		} // Zetta Bytes
		elseif ($bytes >= 1152921504606846976) {
			$bytes = number_format($bytes / 1152921504606846976, 2) . ' EB';
		} // Exa Bytes
		elseif ($bytes >= 1125899906842624) {
			$bytes = number_format($bytes / 1125899906842624, 2) . ' PB';
		} // Peta Bytes
		elseif ($bytes >= 1099511627776) {
			$bytes = number_format($bytes / 1099511627776, 2) . ' TB';
		} // Tera Bytes
		elseif ($bytes >= 1073741824) {
			$bytes = number_format($bytes / 1073741824, 2) . ' GB';
		} // Giga Bytes
		elseif ($bytes >= 1048576) {
			$bytes = number_format($bytes / 1048576, 2) . ' MB';
		} // Mage Bytes
		elseif ($bytes >= 1024) {
			$bytes = number_format($bytes / 1024, 2) . ' KB';
		} //Kilo Bytes
		elseif ($bytes > 1) {
			$bytes .= ' bytes';
		} elseif ($bytes === 1) {
			$bytes .= ' byte';
		} else {
			$bytes = '0 byte';
		}
		return $bytes;
	}

	/**
	 * It's returns $_POST data or null according to the data present
	 * @param string $data
	 * @return mixed|null
	 */
	public function post(string $data)
	{
		if (!empty($this->formLang)) {
			return $_POST[$data . "_" . $this->formLang] ?? null;
		}
		return $_POST[$data] ?? null;
	}

	/**
	 *  It's returns $_GET data or null according to the data present
	 *
	 * @param string $data
	 * @return mixed|null
	 */
	public function get(string $data)
	{
		return $_GET[$data] ?? null;
	}

	/**
	 *  It's returns cleaned $_POST data
	 *
	 * @param string $data
	 * @return string|null
	 */
	public function cleanPost(string $data): ?string
	{
		return $this->cleaner($this->post($data));
	}

	/**
	 * It's clean textarea
	 *
	 * @param string $data
	 * @return string|null
	 */
	public function cleanPostTextarea(string $data): ?string
	{
		return $this->cleanerTextarea($this->post($data));
	}

	/**
	 * It's clean $_GET parameter
	 *
	 * @param string $data
	 * @return string
	 */
	public function cleanGet(string $data): string
	{
		return $this->cleaner($this->get($data));
	}

	/**
	 * It's clean $_POST and return as integer
	 *
	 * @param $data
	 * @return int
	 */
	public function cleanPostInt(string $data): ?int
	{
		return is_numeric($this->post($data)) ? (int)$this->post($data) : NULL;
	}

	/**
	 * It's clean $_GET and return as integer
	 * @param string $data
	 * @return int
	 */
	public function cleanGetInt(string $data): ?int
	{
		return is_numeric($this->get($data)) ? (int)$this->get($data) : NULL;
	}

	/**
	 * It's retursn cleaned $_POST that is an array
	 * @param string $name
	 * @return array|mixed|null[]|string[]|void
	 */
	public function cleanPostArray(string $name)
	{
		if (isset($_POST[$name])) {
			if (is_array($_POST[$name])) {
				return array_map(function ($item) {
					return $this->cleaner($item);
				}, $_POST[$name]);
			}
			return $_POST[$name];
		}
		return NULL;
	}

	/**
	 * It's returns $data if is integer otherwise it's returns null
	 * @param string|int $data
	 * @return false|int
	 */
	public function isInteger($data)
	{
		if (is_numeric($data)) {
			return (int)trim($data);
		}
		return false;
	}

	/**
	 * It returns cURL data by giving URL
	 * @param string $url
	 * @return bool|string
	 */
	public function useCurl(string $url): string
	{
		if (!$this->isUrl($url)) {
			return 'NOT AN URL';
		}
		$curl = curl_init();
		curl_setopt($curl, CURLOPT_URL, $url);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($curl, CURLOPT_TIMEOUT, 10);
		curl_setopt($curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.2.16) Gecko/20110319 Firefox/3.6.16");
		$curlData = curl_exec($curl);
		curl_close($curl);
		return $curlData;
	}

	/**
	 * Refreshes the page after the given time.
	 * @param string $url
	 * @param int $time
	 */
	public function refresh(string $url, int $time = 5): void
	{
		header("Refresh:$time; url=$url");
	}

	/**
	 * Checks if the password complies with the required rules
	 * @param $password
	 * @param string|null $msgKeyText
	 * @return array
	 */
	public function passwordControl($password, string $msgKeyText = null): array
	{
		$password = $this->cleaner($password);
		$errors = array();
		if (empty($password)) {
			$errors[] = $msgKeyText . " boş olamaz.";
		}
		if (!empty($password)) {
			if (strlen($password) < 8) {
				$errors[] = $msgKeyText . " en az 8 karakter olmalıdır.";
			}

			if (strlen($password) >= 8) {
				if (!preg_match("#[0-9]+#", $password)) {
					$errors[] = $msgKeyText . " en az bir rakam içermek zorundadır.";
				}
				if (!preg_match("#[a-z]+#", $password)) {
					$errors[] = $msgKeyText . " en az bir küçük harf içermelidir.";
				}
				if (!preg_match("#[A-Z]+#", $password)) {
					$errors[] = $msgKeyText . " en az bir büyük harf içermelidir.";
				}
			}
		}
		return $errors;
	}

	/**
	 * Telefon numarasını formatlar
	 *
	 * @param int|string $number
	 * @return int|string
	 */
	public function phoneFormat($number, string $countryCode = '+90')
	{

		if (ctype_digit($number) && strlen($number) === 10) {
			$number = $countryCode . substr($number, 0, 3) . ' ' . substr($number, 3, 3) . ' ' . substr($number, 6, 2) . ' ' . substr($number, 8, 2);
		} else if (ctype_digit($number) && strlen($number) === 7) {
			$number = substr($number, 0, 3) . ' ' . substr($number, 3, 4);
		}
		return $number;
	}

	/**
	 * It's return random string
	 *
	 * @param int $length
	 * @return string
	 * @throws Exception
	 */
	public function generateRandomString(int $length = 10): string
	{
		$characters = '0123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ';
		$charactersLength = strlen($characters);
		$randomString = '';
		for ($i = 0; $i < $length; $i++) {
			$randomString .= $characters[random_int(0, $charactersLength - 1)];
		}
		return str_shuffle($randomString);
	}

	/**
	 * Küçük harflerden oluşan string döndürür
	 *
	 * @param int $length
	 * @return string
	 */
	public function generateLowerString(int $length = 10): string
	{
		$characters = 'abcdefghijkmnopqrstuvwxyz';
		$charactersLength = strlen($characters);
		$randomString = '';
		for ($i = 0; $i < $length; $i++) {
			$randomString .= $characters[rand(0, $charactersLength - 1)];
		}
		return $randomString;
	}

	/**
	 * Büyük harflerden oluşan string döndürür
	 *
	 * @param int $length
	 * @return string
	 */
	public function generateUpperString(int $length = 10): string
	{
		$characters = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
		$charactersLength = strlen($characters);
		$randomString = '';
		for ($i = 0; $i < $length; $i++) {
			$randomString .= $characters[rand(0, $charactersLength - 1)];
		}
		return $randomString;
	}

	/**
	 * Sayılardan oluşan string döndürür
	 *
	 * @param int $length
	 * @return string
	 */
	public function generateNumberString(int $length = 10): string
	{
		$characters = '0123456789';
		$charactersLength = strlen($characters);
		$randomString = '';
		for ($i = 0; $i < $length; $i++) {
			$randomString .= $characters[rand(0, $charactersLength - 1)];
		}
		return $randomString;
	}

	/**
	 * Şifre Generate ediyor
	 *
	 * @return string
	 */
	public function generatePassword(): string
	{
		$password = $this->generateNumberString(5) . $this->generateLowerString(3) . $this->generateUpperString(3);
		return str_shuffle($password);
	}

	/**
	 * admin panelde kullanılıyor çok faydalı
	 *
	 * @param $text
	 * @param int $limit
	 * @param string $icon
	 * @return mixed|string
	 */
	public function textModal(string $text, int $limit = 25, string $icon = "fas fa-info-circle ml-2")
	{
		$result = null;
		if (strlen($text) > $limit) {
			$result .= $this->kisalt($text, $limit);
			$uniq = uniqid('un-', true) . time();
			$result .= '  <i class="' . $icon . ' ml-2 table-modal-icon" data-toggle="modal" data-target="#page_modal_' . $uniq . '"></i>';
			$result .= '<div id="page_modal_' . $uniq . '" class="modal fade" tabindex="-1">
                                <div class="modal-dialog  modal-lg modal-dialog-centered modal-dialog-scrollable">
                                    <div class="modal-content">
                                        <div class="modal-header">
                                            <h5 class="modal-title">Detay</h5>
                                            <button type="button" class="close" data-dismiss="modal">&times;</button>
                                        </div>
                                        <div class="modal-body">
                                            <p>' . $text . '</p>             
                                        </div>
                                        <div class="modal-footer">
                                            <button type="button" class="btn btn-outline-danger" data-dismiss="modal">Kapat</button>
                                        </div>
                                    </div>
                                </div>
                            </div>';
		} else {
			$result = $text;
		}
		return $result;
	}

	/**
	 * Veritabanından session lang değerine göre statik metinleri döner.
	 *
	 * @param $key
	 * @return mixed|null
	 */
	public function textManager(string $key)
	{
		global $textManager;
		return ($textManager->{$_SESSION["lang"]}[$key]) ?? NULL;
	}

	/**
	 * @return array
	 */
	public function systemLangKeyValue(): array
	{
		global $projectLanguages;
		$lang_array = array();
		foreach ($projectLanguages as $project_languages_row) {
			$lang_array[$project_languages_row->short_lang] = $project_languages_row->lang;
		}
		return $lang_array;
	}

	/**
	 * Tabloda 0000-00-00 olan date değerleini eler. True ise gerçek bir tarihtir.
	 *
	 * @param $date
	 * @return bool
	 */
	public function isDate($date): bool
	{
		// TODO:: change this to real one
		return $date != "0000-00-00";
	}

	/**
	 * Verilen iki tarih arasındaki tarihleri verilen formata göre döndürür.
	 *
	 * @param string $begin
	 * @param string $end
	 * @param string $format
	 * @return array
	 */
	public function datePeriodStartEnd(string $begin, string $end, string $format = 'Y-m-d'): array
	{
		$period = CarbonPeriod::create($begin, $end);
		$dates = [];
		foreach ($period as $date) {
			$dates[] = $date->format($format);
		}
		return $dates;
	}

	/**
	 * Tarihten günümüze kadar  dizi olarak ayları döner => [2021-01-01 => 'February']
	 *
	 * @param Carbon $start
	 * @return array
	 */
	public function getMonthListFromDate(Carbon $start): array
	{
		$start = $start->startOfMonth();
		$end = Carbon::today()->startOfMonth();

		do {
			$months[$start->format('m-Y')] = $start->format('F');
		} while ($start->addMonth() <= $end);

		return $months;
	}


}