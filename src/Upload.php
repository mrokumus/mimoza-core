<?php

namespace Mrt\MimozaCore;

class Upload
{

	private static Upload $instance;
	public \Verot\Upload\Upload $upload;
	public string $file;

	public static function getInstance(string $name): Upload
	{
		if (!isset(self::$instance)) {
			self::$instance = new self($name);
		}
		return self::$instance;
	}

	public function __construct(string $name)
	{
		$this->upload = new \Verot\Upload\Upload($_FILES[$name],'tr_TR');
	}

	public function rename(string$name): Upload
	{
		$this->upload->file_new_name_body = $name;
		return $this;
	}

	public function options(array $options): Upload
	{
		foreach ($options as $key => $option) {
			$this->upload->{$key} = $option;
		}
		return $this;
	}

	public function resize(int $width, int $height = null, bool $crop = true): Upload
	{
		$this->upload->image_resize = true;
		$this->upload->image_x = $width;
		if ($height) {
			$this->upload->image_y = $height;
			$this->upload->image_ratio_crop = $crop;
		} else {
			$this->upload->image_ratio_y = true;
		}
		return $this;
	}

	public function convert(string $ext): Upload
	{
		$this->upload->image_convert = $ext;
		return $this;
	}

	public function watermark(string $text = null): Upload
	{
		if ($text) {
			$this->upload->image_unsharp = true;
			$this->upload->image_border = '0 0 16 0';
			$this->upload->image_border_color = '#000000';
			$this->upload->image_text = $text;
			$this->upload->image_text_font = 2;
			$this->upload->image_text_position = 'B';
			$this->upload->image_text_padding_y = 2;
		}
		return $this;
	}

	public function prefix(string $prefix): Upload
	{
		$this->upload->file_name_body_pre = $prefix . '_';
		return $this;
	}

	public function allowed(array $mimes): Upload
	{
		$this->upload->allowed = $mimes;
		return $this;
	}

	public function onlyImages(): Upload
	{
		$this->upload->allowed = ['image/*'];
		return $this;
	}

	public function to(string $path): Upload
	{
		if ($this->upload->uploaded) {
			$this->upload->process(dirname(__DIR__) . '/' . $path);
			if ($this->upload->processed) {
				$this->file = $this->upload->file_dst_name;
			}
		}
		return $this;
	}

	public function getFile(): string
	{
		return $this->upload->file_dst_name;
	}

	public function getFileWithPath(): string
	{
		return $this->upload->file_dst_pathname;
	}

	public function error(): string
	{
		$this->upload->process();
		return $this->upload->error;
	}

	public function __destruct()
	{
		$this->upload->clean();
	}

}