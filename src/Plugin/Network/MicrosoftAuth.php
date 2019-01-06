<?php

namespace Drupal\social_auth_microsoft\Plugin\Network;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\Url;
use Drupal\social_api\Plugin\NetworkBase;
use Drupal\social_api\SocialApiException;
use Drupal\social_auth_microsoft\Settings\MicrosoftAuthSettings;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Stevenmaguire\OAuth2\Client\Provider\Microsoft;
use Drupal\Core\Site\Settings;

/**
 * Defines a Network Plugin for Social Auth Microsoft.
 *
 * @package Drupal\simple_microsoft_connect\Plugin\Network
 *
 * @Network(
 *   id = "social_auth_microsoft",
 *   social_network = "Microsoft",
 *   type = "social_auth",
 *   handlers = {
 *     "settings": {
 *       "class": "\Drupal\social_auth_microsoft\Settings\MicrosoftAuthSettings",
 *       "config_id": "social_auth_microsoft.settings"
 *     }
 *   }
 * )
 */
class MicrosoftAuth extends NetworkBase implements MicrosoftAuthInterface {

  /**
   * The logger factory.
   *
   * @var \Drupal\Core\Logger\LoggerChannelFactory
   */
  protected $loggerFactory;

  /**
   * The site settings.
   *
   * @var \Drupal\Core\Site\Settings
   */
  protected $siteSettings;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    return new static(
      $configuration,
      $plugin_id,
      $plugin_definition,
      $container->get('entity_type.manager'),
      $container->get('config.factory'),
      $container->get('logger.factory'),
      $container->get('settings')
    );
  }

  /**
   * MicrosoftAuth constructor.
   *
   * @param array $configuration
   *   A configuration array containing information about the plugin instance.
   * @param string $plugin_id
   *   The plugin_id for the plugin instance.
   * @param array $plugin_definition
   *   The plugin implementation definition.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The entity type manager.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The configuration factory object.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   The logger factory.
   * @param \Drupal\Core\Site\Settings $settings
   *   The site settings.
   */
  public function __construct(array $configuration,
                              $plugin_id,
                              array $plugin_definition,
                              EntityTypeManagerInterface $entity_type_manager,
                              ConfigFactoryInterface $config_factory,
                              LoggerChannelFactoryInterface $logger_factory,
                              Settings $settings) {

    parent::__construct($configuration, $plugin_id, $plugin_definition, $entity_type_manager, $config_factory);

    $this->loggerFactory = $logger_factory;
    $this->siteSettings = $settings;
  }

  /**
   * Sets the underlying SDK library.
   *
   * @return \Stevenmaguire\OAuth2\Client\Provider\Microsoft|false
   *   The initialized 3rd party library instance.
   *
   * @throws SocialApiException
   *   If the SDK library does not exist.
   */
  protected function initSdk() {

    $class_name = 'Stevenmaguire\OAuth2\Client\Provider\Microsoft';
    if (!class_exists($class_name)) {
      throw new SocialApiException(sprintf('The Microsoft Library for the league oAuth not found. Class: %s.', $class_name));
    }

    /* @var \Drupal\social_auth_microsoft\Settings\MicrosoftAuthSettings $settings */
    $settings = $this->settings;

    if ($this->validateConfig($settings)) {
      // All these settings are mandatory.
      $league_settings = [
        'clientId' => $settings->getAppId(),
        'clientSecret' => $settings->getAppSecret(),
        'redirectUri' => Url::fromRoute('social_auth_microsoft.callback')->setAbsolute()->toString(),
      ];

      // Proxy configuration data for outward proxy.
      $proxyUrl = $this->siteSettings->get('http_client_config')['proxy']['http'];
      if ($proxyUrl) {
        $league_settings['proxy'] = $proxyUrl;
      }

      return new Microsoft($league_settings);
    }

    return FALSE;
  }

  /**
   * Checks that module is configured.
   *
   * @param \Drupal\social_auth_microsoft\Settings\MicrosoftAuthSettings $settings
   *   The Microsoft auth settings.
   *
   * @return bool
   *   True if module is configured.
   *   False otherwise.
   */
  protected function validateConfig(MicrosoftAuthSettings $settings) {
    $app_id = $settings->getAppId();
    $app_secret = $settings->getAppSecret();
    if (!$app_id || !$app_secret) {
      $this->loggerFactory
        ->get('social_auth_microsoft')
        ->error('Define App ID and App Secret on module settings.');
      return FALSE;
    }

    return TRUE;
  }

}
