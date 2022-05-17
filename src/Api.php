<?php

namespace Mrt\MimozaCore;

class Api
{

	private Log $log;
	private Database $database;


	public function __construct(Database $database, Log $log)
	{
		// Under construction
		$this->database = $database;
		$this->log = $log;

	}


}