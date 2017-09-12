<?php
namespace Grav\Plugin\LoginOAuth;

use Grav\Common\Grav;
use Grav\Common\User\User;
use Grav\Common\Utils;
use OAuth\ServiceFactory;
use OAuth\Common\Storage\Session;
use OAuth\Common\Consumer\Credentials;
use OAuth\Common\Http\Client\CurlClient;
use RocketTheme\Toolbox\File\File;
use RocketTheme\Toolbox\ResourceLocator\UniformResourceLocator;

/**
 * OAuthLoginController
 *
 * Handles OAuth authentication.
 *
 * @author  RocketTheme
 * @author  Sommerregen <sommerregen@benjamin-regler.de>
 */
class Controller extends \Grav\Plugin\Login\Controller
{
    /**
     * @var string
     */
    public $provider;
    /**
     * @var \OAuth\Common\Storage\Session
     */
    protected $storage;
    /**
     * @var \OAuth\ServiceFactory
     */
    protected $factory;

    /**
     * @var \OAuth\Common\Service\AbstractService
     */
    protected $service;

    /**
     * @var string
     */
    protected $prefix = 'oauth';

    /**
     * @var array
     */
    protected $scopes = [
        'github'   => ['user', 'repo', 'write:repo_hook']
    ];

    /**
     * Constructor.
     *
     * @param Grav   $grav   Grav instance
     * @param string $action The name of the action
     * @param array  $post   An array of values passed to the action
     */
    public function __construct(Grav $grav, $action, $post = null)
    {
        parent::__construct($grav, ucfirst($action), $post);

        // Session storage
        $this->storage = new Session(false, 'oauth_token', 'oauth_state');
        /** @var $serviceFactory \OAuth\ServiceFactory */
        $this->factory = new ServiceFactory();
        // Use curl client instead of fopen stream
        if (extension_loaded('curl')) {
            $this->factory->setHttpClient(new CurlClient());
        }
    }

    /**
     * Performs an OAuth authentication
     */
    public function execute()
    {
        /** @var \Grav\Common\Language\Language */
        $t = $this->grav['language'];
        $provider = strtolower($this->action);
        $config = $this->grav['config']->get('plugins.login-oauth.providers.' . $this->action, []);

        if (isset($config['credentials'])) {
            // Setup the credentials for the requests
            $credentials = new Credentials($config['credentials']['key'], $config['credentials']['secret'], $this->grav['uri']->url(true));
            // Instantiate service using the credentials, http client
            // and storage mechanism for the token
            $scope = isset($this->scopes[$provider]) ? $this->scopes[$provider] : [];
            $this->service = $this->factory->createService($this->action, $credentials, $this->storage, $scope);
        }
        if (!$this->service || empty($config)) {
            $this->login->setMessage($t->translate(['PLUGIN_LOGIN_OAUTH.OAUTH_PROVIDER_NOT_SUPPORTED', $this->action]));

            return true;
        }

        // Check OAuth authentication status
        $authenticated = parent::execute();

        if (is_bool($authenticated)) {
            $this->reset();
            if ($authenticated) {
                $this->login->setMessage($t->translate('PLUGIN_LOGIN.LOGIN_SUCCESSFUL'));
            } else {
                $this->login->setMessage($t->translate('PLUGIN_LOGIN.ACCESS_DENIED'));
            }

            // Redirect to current URI
            $redirect = $this->grav['config']->get('plugins.login.redirect_after_login');
            if (!$redirect) {
                $redirect = $this->grav['session']->redirect_after_login;
            }
            $this->setRedirect($redirect);
        } elseif (!$this->grav['session']->oauth) {
            $this->login->setMessage($t->translate(['PLUGIN_LOGIN_OAUTH.OAUTH_PROVIDER_NOT_SUPPORTED', $this->action]));
        }

        return true;
    }

    /**
     * Reset state of OAuth authentication.
     */
    public function reset()
    {
        /** @var Session */
        $session = $this->grav['session'];
        unset($session->oauth);
        $this->storage->clearAllTokens();
        $this->storage->clearAllAuthorizationStates();
    }

    /**
     * Implements a generic OAuth service provider authentication
     *
     * @param  callable $callback A callable to call when OAuth authentication
     *                            starts
     * @param  string   $oauth    OAuth version to be used for authentication
     *
     * @return null|User          Returns a Grav user instance on success.
     */
    protected function genericOAuthProvider($callback, $oauth = 'oauth2')
    {
        /** @var Session */
        $session = $this->grav['session'];

        switch ($oauth) {
            case 'oauth2':
            default:
                if (empty($_GET['code'])) {
                    // Create a state token to prevent request forgery (CSRF).
                    $state = sha1($this->getRandomBytes(1024, false));
                    $redirect = $this->service->getAuthorizationUri([
                        'state' => $state
                    ]);
                    $this->setRedirect($redirect);
                    // Update OAuth session
                    $session->oauth = $this->action;
                    // Store CSRF in the session for later validation.
                    $this->storage->storeAuthorizationState($this->action, $state);
                } else {
                    // Retrieve the CSRF state parameter
                    $state = isset($_GET['state']) ? $_GET['state'] : null;
                    // This was a callback request from the OAuth2 service, get the token
                    $this->service->requestAccessToken($_GET['code'], $state);

                    return $callback();
                }
                break;
        }

        return;
    }

    /**
     * Implements OAuth authentication for GitHub
     *
     * @return null|\Grav\Common\User\User          Returns a boolean on finished authentication.
     */
    public function oauthGitHub()
    {
        return $this->genericOAuthProvider(function() {
            // Get username, email and language
            $user = json_decode($this->service->request('user'), true);
            $emails = json_decode($this->service->request('user/emails'), true);
            $fullname = !empty($user['name'])?$user['name']:$user['login'];
            $token = $this->storage->retrieveAccessToken('GitHub');

            $dataUser = [
                'id'         => $user['id'],
                'fullname'   => $fullname,
                'email'      => reset($emails),
                'github'     => [
                    'login'      => $user['login'],
                    'avatar_url' => $user['avatar_url'],
                    'location'   => $user['location'],
                    'token'      => $token->getAccessToken()
                ]
            ];

            // Authenticate OAuth user against Grav system.
            return $this->authenticateOAuth($dataUser);
        });
    }

    /**
     * Get the user identifier
     *
     * @param string $id The user ID on the service
     *
     * @return string
     */
    private function getUsername($id)
    {
        $service_identifier = $this->action;
        $user_identifier = $this->grav['inflector']->underscorize($id);
        return strtolower("$service_identifier.$user_identifier");
    }

    /**
     * Authenticate user.
     *
     * @param  string $data             ['fullname'] The user name of the OAuth user
     * @param  string $data             ['id']       The id of the OAuth user
     * @param  string $data             ['email']    The email of the OAuth user
     * @param  string $language                      Language
     *
     * @return bool True if user was authenticated
     */
    protected function authenticateOAuth($data, $language = '')
    {
        $username = $this->getUsername($data['id']);
        $user = User::load($username);
        $password = md5($data['id']);
        $userData = [
            'id'         => $data['id'],
            'username'   => $username,
            'fullname'   => $data['fullname'],
            'email'      => $data['email'],
            'lang'       => $language,
            'github'     => [
                'login'      => $data['github']['login'],
                'avatar_url' => $data['github']['avatar_url'],
                'location'   => $data['github']['location'],
                'token'      => $data['github']['token']
            ]
        ];

        $id = $data['id'];
        $data['password'] = md5($id);
        $data['state'] = 'enabled';

        if (!$user->exists()) {
            // Create the user
            $userData['member_since'] = time();
            $user = $this->login->register(Utils::arrayMergeRecursiveUnique($userData, $data));

            $authenticated = true;
            $user->authenticated = true;
            $user->save();

        } else {
            $authenticated = $user->authenticate($password);
            // Save new email if different.
            if ($authenticated) {
                $mergeData = Utils::arrayMergeRecursiveUnique($user->toArray(), $userData);


                if (!isset($mergeData['member_since']) && !isset($data['member_since'])) {
                    $mergeData['member_since'] = time();
                }

                $user = $this->login->register(Utils::arrayMergeRecursiveUnique($mergeData, $data));

                $authenticated = true;
                $user->authenticated = true;
                $user->save();
            }
        }

        $avatar = 'user://media/' . $username . '.png';
        if (!file_exists($avatar)) {
            /** @var UniformResourceLocator $locator */
            $locator = $this->grav['locator'];
            $file = File::instance($locator->findResource($avatar, true, true));
            $file->save(file_get_contents($userData['github']['avatar_url']));
        }

        // Store user in session
        if ($authenticated) {
            $this->grav['session']->user = $user;
            unset($this->grav['user']);
            $this->grav['user'] = $user;

            $this->rememberMe->createCookie($username);
        }

        return $authenticated;
    }

    /**
     * Generates Random Bytes for the given $length.
     *
     * @param  int  $length The number of bytes to generate
     * @param  bool $secure Return cryptographic secure string or not
     *
     * @return string
     *
     * @throws InvalidArgumentException when an invalid length is specified.
     * @throws RuntimeException when no secure way of making bytes is posible
     */
    protected function getRandomBytes($length = 0, $secure = true)
    {
        if ($length < 1) {
            throw new \InvalidArgumentException('The length parameter must be a number greater than zero!');
        }
        /**
         * Our primary choice for a cryptographic strong randomness function is
         * openssl_random_pseudo_bytes.
         */
        if (function_exists('openssl_random_pseudo_bytes')) {
            $bytes = openssl_random_pseudo_bytes($length, $sec);
            if ($sec === true) {
                return $bytes;
            }
        }
        /**
         * If mcrypt extension is available then we use it to gather entropy from
         * the operating system's PRNG. This is better than reading /dev/urandom
         * directly since it avoids reading larger blocks of data than needed.
         * Older versions of mcrypt_create_iv may be broken or take too much time
         * to finish so we only use this function with PHP 5.3.7 and above.
         * @see https://bugs.php.net/bug.php?id=55169
         */
        if (function_exists('mcrypt_create_iv') && (strtolower(substr(PHP_OS, 0,
                    3)) !== 'win' || version_compare(PHP_VERSION, '5.3.7') >= 0)
        ) {
            $bytes = mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
            if ($bytes !== false) {
                return $bytes;
            }
        }
        if ($secure) {
            throw new \RuntimeException('There is no possible way of making secure bytes');
        }

        /**
         * Fallback (not really secure, but better than nothing)
         */
        return hex2bin(substr(str_shuffle(str_repeat('0123456789abcdef', $length * 16)), 0, $length));
    }

    public function clearRememberMe($username)
    {
        $this->rememberMe->clearCookie();
        $this->rememberMe->getStorage()->cleanAllTriplets($username);
    }
}
