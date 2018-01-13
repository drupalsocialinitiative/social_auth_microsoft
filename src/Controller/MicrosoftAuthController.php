<?php

namespace Drupal\social_auth_microsoft\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\social_api\Plugin\NetworkManager;
use Drupal\social_auth\SocialAuthDataHandler;
use Drupal\social_auth\SocialAuthUserManager;
use Drupal\social_auth_microsoft\MicrosoftAuthManager;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Returns responses for Simple Microsoft Connect module routes.
 */
class MicrosoftAuthController extends ControllerBase {

  /**
   * The network plugin manager.
   *
   * @var \Drupal\social_api\Plugin\NetworkManager
   */
  private $networkManager;

  /**
   * The user manager.
   *
   * @var \Drupal\social_auth\SocialAuthUserManager
   */
  private $userManager;

  /**
   * The microsoft authentication manager.
   *
   * @var \Drupal\social_auth_microsoft\MicrosoftAuthManager
   */
  private $microsoftManager;

  /**
   * Used to access GET parameters.
   *
   * @var \Symfony\Component\HttpFoundation\RequestStack
   */
  private $request;

  /**
   * The Social Auth Data Handler.
   *
   * @var \Drupal\social_auth\SocialAuthDataHandler
   */
  private $dataHandler;

  /**
   * MicrosoftAuthController constructor.
   *
   * @param \Drupal\social_api\Plugin\NetworkManager $network_manager
   *   Used to get an instance of social_auth_microsoft network plugin.
   * @param \Drupal\social_auth\SocialAuthUserManager $user_manager
   *   Manages user login/registration.
   * @param \Drupal\social_auth_microsoft\MicrosoftAuthManager $microsoft_manager
   *   Used to manage authentication methods.
   * @param \Symfony\Component\HttpFoundation\RequestStack $request
   *   Used to access GET parameters.
   * @param \Drupal\social_auth\SocialAuthDataHandler $data_handler
   *   SocialAuthDataHandler object.
   */
  public function __construct(NetworkManager $network_manager,
                              SocialAuthUserManager $user_manager,
                              MicrosoftAuthManager $microsoft_manager,
                              RequestStack $request,
                              SocialAuthDataHandler $data_handler) {

    $this->networkManager = $network_manager;
    $this->userManager = $user_manager;
    $this->microsoftManager = $microsoft_manager;
    $this->request = $request;
    $this->dataHandler = $data_handler;

    // Sets the plugin id.
    $this->userManager->setPluginId('social_auth_microsoft');

    // Sets the session keys to nullify if user could not logged in.
    $this->userManager->setSessionKeysToNullify(['access_token', 'oauth2state']);
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('plugin.network.manager'),
      $container->get('social_auth.user_manager'),
      $container->get('social_auth_microsoft.manager'),
      $container->get('request_stack'),
      $container->get('social_auth.data_handler')
    );
  }

  /**
   * Response for path 'user/login/microsoft'.
   *
   * Redirects the user to Microsoft for authentication.
   */
  public function redirectToMicrosoft() {
    /* @var \Stevenmaguire\OAuth2\Client\Provider\Microsoft|false $microsoft */
    $microsoft = $this->networkManager->createInstance('social_auth_microsoft')->getSdk();

    // If microsoft client could not be obtained.
    if (!$microsoft) {
      drupal_set_message($this->t('Social Auth Microsoft not configured properly. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    // Microsoft service was returned, inject it to $microsoftManager.
    $this->microsoftManager->setClient($microsoft);

    // Generates the URL where the user will be redirected for Microsoft login.
    // If the user did not have email permission granted on previous attempt,
    // we use the re-request URL requesting only the email address.
    $microsoft_login_url = $this->microsoftManager->getMicrosoftLoginUrl();

    $state = $this->microsoftManager->getState();

    $this->dataHandler->set('oauth2state', $state);

    return new TrustedRedirectResponse($microsoft_login_url);
  }

  /**
   * Response for path 'user/login/microsoft/callback'.
   *
   * Microsoft returns the user here after user has authenticated in Microsoft.
   */
  public function callback() {
    // Checks if user cancel login via Microsoft.
    $error = $this->request->getCurrentRequest()->get('error');
    if ($error == 'access_denied') {
      drupal_set_message($this->t('You could not be authenticated.'), 'error');
      return $this->redirect('user.login');
    }

    /* @var \Stevenmaguire\OAuth2\Client\Provider\Microsoft|false $microsoft */
    $microsoft = $this->networkManager->createInstance('social_auth_microsoft')->getSdk();

    // If Microsoft client could not be obtained.
    if (!$microsoft) {
      drupal_set_message($this->t('Social Auth Microsoft not configured properly. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    $state = $this->dataHandler->get('oauth2state');

    // Retreives $_GET['state'].
    $retrievedState = $this->request->getCurrentRequest()->query->get('state');
    if (empty($retrievedState) || ($retrievedState !== $state)) {
      $this->userManager->nullifySessionKeys();
      drupal_set_message($this->t('Microsoft login failed. Unvalid OAuth2 State.'), 'error');
      return $this->redirect('user.login');
    }

    // Saves access token to session.
    $this->dataHandler->set('access_token', $this->microsoftManager->getAccessToken());

    $this->microsoftManager->setClient($microsoft)->authenticate();

    // Gets user's info from Microsoft API.
    /* @var \Stevenmaguire\OAuth2\Client\Provider\MicrosoftResourceOwner $microsoft_profile */
    if (!$microsoft_profile = $this->microsoftManager->getUserInfo()) {
      drupal_set_message($this->t('Microsoft login failed, could not load Microsoft profile. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    return $this->userManager->authenticateUser($microsoft_profile->getName(), $microsoft_profile->getEmail(), $microsoft_profile->getId(), $this->microsoftManager->getAccessToken());
  }

}
