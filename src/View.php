<?php

namespace Mrt\MimozaCore;

class View
{

	/**
	 * It's return view
	 *
	 * @param string $view view name
	 * @return string view path
	 */
	private static function view(string $view): string
	{
		global $settings;
		return ROOT_PATH . '/app/View/' . $settings->theme . '/' . $view . '.php';
	}

	/**
	 * It's return view
	 *
	 * @param string $view view name
	 * @return string view path
	 */
	private static function backendView(string $view): string
	{
		return ROOT_PATH . '/admin/View/project/' . $view . '.php';
	}

	/**
	 * It's return error view
	 *
	 * @param int $errorCode
	 * @return string
	 */
	private static function errorView(int $errorCode): string
	{
		global $settings;
		return ROOT_PATH . '/app/View/errors/' . $errorCode . '.php';
	}

	/**
	 * It's return layout
	 *
	 * @param string $view
	 * @param array|null $data
	 * @param string $layout
	 * @return mixed
	 */
	public static function layout(string $view, array $data = null, string $layout = 'main')
	{
		global $constants;
		global $metaTag;
		global $functions;
		global $settings;
		global $siteManager;
		global $system;
		global $projectLanguages;
		global $session;
		global $fileTypePath;
		global $loggedUser;
		global $socialMedia;
		global $message;
		global $menuItems;
		global $form;
		$form = new Form();

		$data['view'] = self::view($view);
		$data = (object)$data;
		return require ROOT_PATH . "/app/View/layouts/{$layout}.php";
	}

	/**
	 * It's return layout
	 *
	 * @param string $view
	 * @param array|null $data
	 * @param string $layout
	 * @return mixed
	 */
	public static function backend(string $view, array $data = null, string $layout = 'main')
	{

		if (!isset($_SESSION['theme'])) {
			$_SESSION['theme'] = 'light-layout';
		}

		// TODO:: değiştir
		require ROOT_PATH . "/includes/Statics/Admin.php";

		global $metaTag;
		global $functions;
		global $settings;
		global $siteManager;
		global $system;
		global $session;
		global $fileTypePath;
		global $loggedUser;
		global $socialMedia;
		global $message;
		global $betaMenu;
		global $adminSystem;
		global $listPermissionKey;
		global $editPermissionKey;
		global $deletePermissionKey;
		global $projectLanguages;
		global $form;
		global $admin_text;
		global $constants;
		global $userHeaderTopImg;
		global $menu;
		$form = new AdminForm();

		$data['theme'] = $_SESSION['theme'];
		$data['view'] = self::backendView($view);
		$data = (object)$data;
		return require ROOT_PATH . "/admin/View/layouts/{$layout}.php";
	}

	/**
	 * It's return error layout
	 *
	 * @param string $view
	 * @param array|null $data
	 * @param string $layout
	 * @return mixed
	 */
	public static function error(int $errorCode, array $data = null, string $layout = 'error')
	{

		if (!isset($_SESSION['theme'])) {
			$_SESSION['theme'] = 'light-layout';
		}

		global $settings;
		global $system;
		$data['view'] = self::errorView($errorCode);
		$data = (object)$data;
		return require ROOT_PATH . "/app/View/layouts/{$layout}.php";
	}


}