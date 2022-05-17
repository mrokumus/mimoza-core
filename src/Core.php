<?php

namespace Mrt\MimozaCore;

class Core
{

	/**
	 * @param $index
	 * @return false|mixed
	 */
	public function route($index)
	{
		global $route;
		return $route[$index] ?? false;
	}

	/**
	 * It's return controller path
	 *
	 * @param string $controllerName
	 * @return string
	 */
	public function controller(string $controllerName): string
	{
		$controllerName = strtolower($controllerName);
		return ROOT_PATH . '/app/Controller/' . $controllerName . '.php';
	}

	/**
	 * @param $controllerName
	 * @return string
	 */
	public function adminController($controllerName): string
	{
		$controllerName = strtolower($controllerName);
		return ROOT_PATH . '/admin/Controller/' . $controllerName . '.php';
	}

	/**
	 * It's return view url
	 *
	 * @param string $viewName
	 * @return string
	 */
	public function view(string $viewName): string
	{
		global $settings;
		return ROOT_PATH . '/app/View/' . $settings->theme . '/' . $viewName . '.php';
	}

	/**
	 * @param $viewName
	 * @return string
	 */
	public function adminView($viewName): string
	{
		return ROOT_PATH . '/admin/View/project/' . $viewName . '.php';
	}

	/**
	 * It's return public url
	 *
	 * @param string $url
	 * @return string
	 */
	public function publicUrl(string $url = ''): string
	{
		global $settings;
		return SITE_URL . '/public/' . $settings->theme . '/' . $url;
	}

	/**
	 * @param string $url
	 * @return string
	 */
	public function adminPublicUrl(string $url = ''): string
	{
		return SITE_URL . '/vendor/' . $url;
	}

	public function url($url = ''): string
	{
		return SITE_URL . '/' . $_SESSION['lang'] . '/' . $url;
	}

	/**
	 * @param string $url
	 * @return string
	 */
	public function adminUrl(string $url = ''): string
	{
		return SITE_URL . '/admin/' . $url;
	}

	/**
	 * It's return file path
	 *
	 * @param string $filePath
	 * @return string
	 */
	public function path(string $filePath = ''): string
	{
		return ROOT_PATH . '/' . $filePath;
	}

	/**
	 * It's return public path
	 *
	 * @param string $path
	 * @param bool $theme Theme folder.
	 * @return string
	 */
	public function publicPath(string $path = '', bool $theme = true): string
	{
		global $settings;
		$themePath = ($theme) ? $settings->theme . '/' : '';

		return ROOT_PATH . '/public/' . $themePath . $path;
	}

	public function uploadUrl(string $url): string
	{
		return SITE_URL . '/uploads/' . $url;
	}

	/**
	 * For change system languages
	 *
	 * @param string $language
	 * @return string
	 */
	public function setLanguage(string $language): string
	{
		unset($_SESSION['lang']);
		$_SESSION['lang'] = $language;
		$uri = array_values(array_filter(explode('/', $_SERVER['REQUEST_URI'])));
		$uri[0] = $language;
		return SITE_URL . '/' . implode('/', $uri);
	}

	/**
	 * For use nav items a specific class
	 *
	 * @param string $url
	 * @return bool
	 */
	public function isUrlActive(string $url): bool
	{
		$uri = array_values(array_filter(explode('/', $_SERVER['REQUEST_URI'])));
		return isset($uri[1]) && $url === $uri[1];

	}

	/**
	 * It's return static translation based on system languages.
	 *
	 * @param $englishVersion
	 * @return string
	 */
	public function __($englishVersion): string
	{
		try {
			$langJson = json_decode(file_get_contents($this->publicPath('languages/' . $_SESSION['lang'] . '.json')), false, 512, JSON_THROW_ON_ERROR);
		} catch (\JsonException $e) {

		}
		return $langJson->{$englishVersion} ?? $englishVersion;
	}

	/**
	 * It's include error page that is specified by given code page and exit
	 *
	 * @param $code
	 */
	public function abort($code): void
	{
		if (file_exists(ROOT_PATH . '/public/errors/' . $code . '.php')) {
			http_response_code($code);
			include "public/errors/" . $code . ".php";
			exit();
		}
		echo 'Lütfen ' . $code . ' http kodu için public/error/ klasörü altına hata sayfasını ekleyiniz.';
		exit;
	}

}
