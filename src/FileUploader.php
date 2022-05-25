<?php

namespace Mrt\MimozaCore;

use Verot\Upload\Upload;

class FileUploader
{

	/**
	 * File upload path array
	 *
	 * @var array
	 */
	public array $uploadPathInfo = [];

	/**
	 * File uploads folder key. It's defined in Mrt\MimozaCore\Constants
	 *
	 * @var string
	 */
	public string $uploadFolder = "default";

	/**
	 * $_FILES key
	 *
	 * @var string
	 */
	public string $globalFileName = "img";

	/**
	 * For resize images
	 *
	 * @var bool
	 */
	public bool $resize = false;

	/**
	 * Resize width
	 *
	 * @var int
	 */
	public int $width = 1366;

	/**
	 * resize height
	 *
	 * @var int
	 */
	public int $height = 768;

	/**
	 * Max file upload size
	 *
	 * @var int
	 */
	public int $maxFileSize = 2;

	/**
	 * File type to upload
	 *
	 * @var string
	 */
	public string $uploadType = "img";

	/**
	 * File compression
	 *
	 * @var bool
	 */
	public bool $compressor = false;

	/**
	 * File extensions to compression
	 *
	 * @var string[]
	 */
	public array $compressorExtension = ["png", "jpg", "jpeg"];

	/**
	 * Compression level
	 * @var int
	 */
	public int $compressorLevel = 4;

	/**
	 * For gallery file upload
	 *
	 * @var null|int
	 */
	public ?int $galleryId = NULL;


	/**
	 *
	 * @param $file_type_path
	 */
	public function __construct($file_type_path)
	{
		$this->uploadPathInfo = $file_type_path;
	}

	/**
	 * @return array|false
	 */
	public function fileUpload()
	{
		if (isset($_FILES[$this->globalFileName])) {
			$url = $this->uploadPathInfo["default"]["full_path"];
			if (array_key_exists($this->uploadFolder, $this->uploadPathInfo)) {
				$url = $this->uploadPathInfo[$this->uploadFolder]["full_path"] . ($this->galleryId > 0 ? $this->galleryId . "/" : null);
			}
			$result = array();
			$image = $_FILES[$this->globalFileName];
			$image_name = uniqid('', true) . "-" . time();
			$handle = new Upload($image, "tr_TR");
			if ($handle->uploaded) {
				$handle->file_max_size = 1024 * 1024 * $this->maxFileSize;
				$handle->file_new_name_body = $image_name;

				$handle->image_ratio = false;
				if ($this->resize) {
					$handle->image_resize = true;
					//$handle->image_ratio_crop = false;
					$handle->image_ratio_crop = true;
					$handle->image_x = $this->width;
					$handle->image_y = $this->height;
					//arka alanı beyaz yapar
					//$handle->image_ratio_fill = true;
				}
				if ($this->uploadType === "img") {
					$handle->allowed = array("image/jpeg", "image/png", "image/jpg");
				} elseif ($this->uploadType === "pdf") {
					$handle->allowed = array("application/pdf");
				} elseif ($this->uploadType === "pdf_and_img") {
					$handle->allowed = array("application/pdf", "image/jpeg", "image/png", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
				} elseif ($this->uploadType === "word") {
					$handle->allowed = array("application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
				} elseif ($this->uploadType === "pdf_word_image_excel") {
					$handle->allowed = array("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/excel", "application/pdf", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "image/jpeg", "image/png", "image/jpg");
				} elseif ($this->uploadType === "mp3") {
					$handle->allowed = array("audio/*");
				} else {
					$handle->allowed = array("image/jpeg", "image/png", "image/jpg");
				}

				$handle->Process($url);
				$img_path = $handle->file_dst_name;
				if ($handle->processed) {
					$img_name_explode = explode(".", $img_path);
					$extension = end($img_name_explode);

					if ($this->compressor && in_array($extension, $this->compressorExtension, true)) {
						if (!file_exists($url . "compressed") && !mkdir($concurrentDirectory = $url . "compressed", 0777) && !is_dir($concurrentDirectory)) {
							throw new \RuntimeException(sprintf('Directory "%s" was not created', $concurrentDirectory));
						}
						// setting
						$setting_img = array(
							'directory' => $url . "compressed", // directory file compressed output
							'file_type' => array( // file format allowed
								'image/jpeg',
								'image/png',
								'image/gif'
							)
						);
						// create object
						$ImgCompressor = new ImgCompressor($setting_img);
						$ImgCompressor->run($url . $img_path, $extension, $this->compressorLevel, $img_path);
					}
					//resim yüklenmişse çalışır
					$result["result"] = 1;
					$result["img_name"] = $img_path;

				} else {
					//resim yüklenememişse çalışır
					$result["result"] = 2;
					$result["result_message"] = $handle->error;
				}
			} else {
				//resim seçilmemişse çalışır
				$result["result"] = 3;
				$result["result_message"] = $handle->error;
			}
			return $result;
		}
		return false;
	}
}