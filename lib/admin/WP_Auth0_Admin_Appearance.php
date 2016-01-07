<?php 

class WP_Auth0_Admin_Appearance extends WP_Auth0_Admin_Generic {

  const APPEARANCE_DESCRIPTION = 'Settings related to the way the login widget is shown.';

  protected $actions_middlewares = array(
    'basic_validation',
  );

  public function init() {

    $this->init_option_section( '', 'appearance', array(

      array( 'id' => 'wpa0_form_title', 'name' => 'Form Title', 'function' => 'render_form_title' ),
      array( 'id' => 'wpa0_social_big_buttons', 'name' => 'Show big social buttons', 'function' => 'render_social_big_buttons' ),
      array( 'id' => 'wpa0_icon_url', 'name' => 'Icon URL', 'function' => 'render_icon_url' ),
      array( 'id' => 'wpa0_gravatar', 'name' => 'Enable Gravatar integration', 'function' => 'render_gravatar' ),
      array( 'id' => 'wpa0_custom_css', 'name' => 'Customize the Login Widget CSS', 'function' => 'render_custom_css' ),
      array( 'id' => 'wpa0_custom_js', 'name' => 'Customize the Login Widget with custom JS', 'function' => 'render_custom_js' ),
      array( 'id' => 'wpa0_username_style', 'name' => 'Username style', 'function' => 'render_username_style' ),
      array( 'id' => 'wpa0_remember_last_login', 'name' => 'Remember last login', 'function' => 'render_remember_last_login' ),
      array( 'id' => 'wpa0_dict', 'name' => 'Translation', 'function' => 'render_dict' ),

    ) );

    $options_name = $this->a0_options->get_options_name();
    register_setting( $options_name . '_appearance', $options_name, array( $this, 'input_validator' ) );
  }

  public function render_remember_last_login() {
    $v = absint( $this->a0_options->get( 'remember_last_login' ) );

    echo $this->render_a0_switch("wpa0_remember_last_login", "remember_last_login", 1, 1 == $v);
  ?>
    <div class="subelement">
      <span class="description">
        <?php echo __( 'Request for SSO data and enable "Last time you signed in with[...]" message.', WPA0_LANG ); ?>
        <a target="_blank" href="https://github.com/auth0/lock/wiki/Auth0Lock-customization#rememberlastlogin-boolean"><?php echo __( 'More info', WPA0_LANG ); ?></a>
      </span>
    </div>
  <?php
  }

  public function render_form_title() {
    $v = $this->a0_options->get( 'form_title' );
    ?>
      <input type="text" name="<?php echo $this->a0_options->get_options_name(); ?>[form_title]" id="wpa0_form_title" value="<?php echo esc_attr( $v ); ?>"/>
      <div class="subelement">
        <span class="description"><?php echo __( 'This is the title for the login widget', WPA0_LANG ); ?></span>
      </div>
    <?php
  }

  public function render_dict() {
    $v = $this->a0_options->get( 'dict' );
    ?>
      <textarea name="<?php echo $this->a0_options->get_options_name(); ?>[dict]" id="wpa0_dict"><?php echo esc_attr( $v ); ?></textarea>
      <div class="subelement">
        <span class="description"><?php echo __( 'This is the widget\'s dict param.', WPA0_LANG ); ?><a target="_blank" href="https://auth0.com/docs/libraries/lock/customization#4"><?php echo __( 'More info', WPA0_LANG ); ?></a></span>
      </div>
    <?php
  }

  public function render_custom_css() {
    $v = $this->a0_options->get( 'custom_css' );
    ?>
      <textarea name="<?php echo $this->a0_options->get_options_name(); ?>[custom_css]" id="wpa0_custom_css"><?php echo esc_attr( $v ); ?></textarea>
      <div class="subelement">
        <span class="description"><?php echo __( 'This should be a valid CSS to customize the Auth0 login widget. ', WPA0_LANG ); ?><a target="_blank" href="https://github.com/auth0/wp-auth0#can-i-customize-the-login-widget"><?php echo __( 'More info', WPA0_LANG ); ?></a></span>
      </div>
    <?php
  }

  public function render_custom_js() {
    $v = $this->a0_options->get( 'custom_js' );
    ?>
      <textarea name="<?php echo $this->a0_options->get_options_name(); ?>[custom_js]" id="wpa0_custom_js"><?php echo esc_attr( $v ); ?></textarea>
      <div class="subelement">
        <span class="description"><?php echo __( 'This should be a valid JS to customize the Auth0 login widget to, for example, add custom buttons. ', WPA0_LANG ); ?><a target="_blank" href="https://auth0.com/docs/hrd#3"><?php echo __( 'More info', WPA0_LANG ); ?></a></span>
      </div>
    <?php
  }

  public function render_username_style() {
    $v = $this->a0_options->get( 'username_style' );
    ?>
      <input type="radio" name="<?php echo $this->a0_options->get_options_name(); ?>[username_style]" id="wpa0_username_style_email" value="email" <?php echo (esc_attr( $v ) == 'email' ? 'checked="true"' : '' ); ?> />
      <label for="wpa0_username_style_email"><?php echo __( 'Email', WPA0_LANG ); ?></label>

      <input type="radio" name="<?php echo $this->a0_options->get_options_name(); ?>[username_style]" id="wpa0_username_style_username" value="username" <?php echo (esc_attr( $v ) == 'username' ? 'checked="true"' : '' ); ?> />
      <label for="wpa0_username_style_username"><?php echo __( 'Username', WPA0_LANG ); ?></label>

      <div class="subelement">
        <span class="description">
          <?php echo __( 'If you don\'t want to validate that the user enters an email, just set this to username.', WPA0_LANG ); ?>
          <a target="_blank" href="https://github.com/auth0/lock/wiki/Auth0Lock-customization#usernamestyle-string"><?php echo __( 'More info', WPA0_LANG ); ?></a>
        </span>
      </div>
    <?php
  }

  public function render_social_big_buttons() {
    $v = absint( $this->a0_options->get( 'social_big_buttons' ) );

    echo $this->render_a0_switch("wpa0_social_big_buttons", "social_big_buttons", 1, 1 == $v);
  }

  public function render_gravatar() {
    $v = absint( $this->a0_options->get( 'gravatar' ) );

    echo $this->render_a0_switch("wpa0_gravatar", "gravatar", 1, 1 == $v);
    ?>  
      
      <div class="subelement">
        <span class="description">
          <?php echo __( 'Read more about the gravatar integration ', WPA0_LANG ); ?>
          <a target="_blank" href="https://github.com/auth0/lock/wiki/Auth0Lock-customization#gravatar-boolean"><?php echo __( 'HERE', WPA0_LANG ); ?></a></span>
      </div>
    <?php
  }

  public function render_icon_url() {
    $v = $this->a0_options->get( 'icon_url' );
    ?>
      <input type="text" name="<?php echo $this->a0_options->get_options_name(); ?>[icon_url]" id="wpa0_icon_url" value="<?php echo esc_attr( $v ); ?>"/>
      <a target="_blank" href="javascript:void(0);" id="wpa0_choose_icon" class="button-secondary"><?php echo __( 'Choose Icon', WPA0_LANG ); ?></a>
      <div class="subelement">
        <span class="description"><?php echo __( 'The icon should be 32x32 pixels!', WPA0_LANG ); ?></span>
      </div>
    <?php
  }

  public function render_appearance_description() {
    ?>

    <p class=\"a0-step-text\"><?php echo self::APPEARANCE_DESCRIPTION; ?></p>

    <?php
  }

  public function basic_validation( $old_options, $input ) {
    $input['form_title'] = sanitize_text_field( $input['form_title'] );
    $input['icon_url'] = esc_url( $input['icon_url'], array( 'http', 'https' ) );
    $input['social_big_buttons'] = ( isset( $input['social_big_buttons'] ) ? $input['social_big_buttons'] : 0 );
    $input['gravatar'] = ( isset( $input['gravatar'] ) ? $input['gravatar'] : 0 );
    $input['remember_last_login'] = ( isset( $input['remember_last_login'] ) ? $input['remember_last_login'] : 0 );

    if ( trim( $input['dict'] ) !== '' ) {
      if ( strpos( $input['dict'], '{' ) !== false && json_decode( $input['dict'] ) === null ) {
        $error = __( 'The Translation parameter should be a valid json object.', WPA0_LANG );
        $this->add_validation_error( $error );
      }
    }

    // if ( trim( $input['extra_conf'] ) !== '' ) {
    //  if ( json_decode( $input['extra_conf'] ) === null ) {
    //    $error = __( 'The Extra settings parameter should be a valid json object.', WPA0_LANG );
    //    $this->add_validation_error( $error );
    //  }
    // }

    return $input;
  }


}
