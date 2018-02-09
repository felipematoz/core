<?php
/**
 * @author Thomas Müller <thomas.mueller@tmit.eu>
 *
 * @copyright Copyright (c) 2018, ownCloud GmbH
 * @license AGPL-3.0
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */


namespace OC\User;


use OCP\Authentication\IAuthModule;
use OCP\IRequest;
use OCP\IUserManager;

class BasicAuthModule implements IAuthModule {

	/** @var IUserManager */
	private $manager;
	/** @var Session */
	private $session;

	/**
	 * BasicAuthModule constructor.
	 *
	 * @param IUserManager $manager
	 * @param Session $session
	 */
	public function __construct(IUserManager $manager, Session $session) {
		$this->manager = $manager;
		$this->session = $session;
	}

	/**
	 * @inheritdoc
	 */
	public function auth(IRequest $request) {
		if (empty($request->server['PHP_AUTH_USER']) || empty($request->server['PHP_AUTH_PW'])) {
			return null;
		}

		$user = $request->server['PHP_AUTH_USER'];
		$password = $request->server['PHP_AUTH_PW'];
		// reuse login because this method handles app passwords as well as regular credentials
		if (!$this->session->login($user, $password, false) ) {
			$users = $this->manager->getByEmail($user);
			if (count($users) === 1) {
				if (!$this->session->login($users[0]->getUID(), $password, false)) {
					throw new \Exception('Invalid credentials');
				}
			} else {
				throw new \Exception('Invalid credentials');
			}
		}

		return $this->manager->get($request->server['PHP_AUTH_USER']);
	}

	/**
	 * @inheritdoc
	 */
	public function getUserPassword(IRequest $request) {
		if (empty($request->server['PHP_AUTH_USER']) || empty($request->server['PHP_AUTH_PW'])) {
			return '';
		}

		if ($this->session->getSession()->exists('app_password')) {
			// TODO: use proper password
			throw new \Exception('Not implemented yet');
		}
		return $request->server['PHP_AUTH_PW'];
	}
}
