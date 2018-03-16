<?php

namespace Drupal\Tests\social_auth_microsoft\Functional;

use Drupal\social_api\SocialApiSettingsFormBaseTest;

/**
 * Test Social Auth Microsoft settings form.
 *
 * @group social_auth
 *
 * @ingroup social_auth_microsoft
 */
class SocialAuthMicrosoftSettingsFormTest extends SocialApiSettingsFormBaseTest {
  /**
   * Modules to enable.
   *
   * @var array
   */
  public static $modules = ['social_auth_microsoft'];

  /**
   * {@inheritdoc}
   */
  protected function setUp() {
    $this->module = 'social_auth_microsoft';
    $this->socialNetwork = 'microsoft';
    $this->moduleType = 'social-auth';

    parent::setUp();
  }

  /**
   * {@inheritdoc}
   */
  public function testIsAvailableInIntegrationList() {
    $this->fields = ['client_id', 'client_secret'];

    parent::testIsAvailableInIntegrationList();
  }

  /**
   * {@inheritdoc}
   */
  public function testSettingsFormSubmission() {
    $this->edit = [
      'app_id' => $this->randomString(10),
      'app_secret' => $this->randomString(10),
    ];

    parent::testSettingsFormSubmission();
  }

}
