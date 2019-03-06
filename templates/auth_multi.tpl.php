<?php

if (!isset($this->data['autofocus'])) {
    $this->data['autofocus'] = 'username';
}

$this->data['header'] = $this->t('{notakey:notakey:auth_header}');
$this->includeAtTemplateBase('includes/header.php');

// echo '<script type="text/javascript" src="'.$this->data['baseurlpath'].'resources/jquery-1.8.js"></script>';
echo($this->data['js_block']);
if (count($this->data['warning_messages']) > 0) { ?>
        <?php foreach($this->data['warning_messages'] as $err){ ?>
        <div class="ui-tabs ui-widget ui-widget-content ui-corner-all" style="background: #f5f5f5;">
            <div class="float-l">
                <img src="/<?php echo $this->data['baseurlpath']; ?>resources/icons/experience/gtk-dialog-error.48x48.png" class="erroricon" style="margin: 15px;" />
            </div>
            <div style="padding-top: 0.7rem; padding-left: 1rem;" class="float-l">
                <h2><?php echo $this->t('{login:error_header}'); ?></h2>
            </div>
            <div class="clearfix"></div>
            <div style="padding: 1rem;">
                <p><?php echo $err; ?> </p>
            </div>
            <div class="clearfix"></div>
            <!--  <div style="clear:both;"></div> -->
        </div>
        <?php } ?>
<?php
}
?>
<h2 id="authHeaderTitle"><?php echo $this->t('{notakey:notakey:login_header}'); ?></h2>
<p class="logintext"><?php echo $this->t('{notakey:notakey:login_message}'); ?></p>
<div id="authContent">
<?php
if(!$this->data['state']['notakey:stageOneComplete'] || $this->data['auth_state'] != 'pending'){
?>
    <div id="loginTableView">
        <form action="/<?php echo $this->data['baseurlpath']; ?>module/notakey/auth" id="loginPostForm" method="post">
            <?php
            if(count($this->data['service_list']) > 1){
            ?>
            <div class="control-group float-l" style="padding-top: 15px;"><?php echo $this->t('{notakey:notakey:select_auth_message}') ?></div>
            <div class="clearfix"></div>

            <?php foreach($this->data['service_list'] as $app_id => $s ){ ?>
            <div class="control-group float-l service-logo">
                <label class="service-selector">
                    <input type="radio" name="service_id" value="<?php echo $app_id; ?>" <?php if(isset($this->data['selected_service']) && $app_id == $this->data['selected_service']){ ?>checked="checked"<?php } ?> />
                    <img alt="<?php echo $s['name']; ?>"  src="<?php echo $s['service_logo']; ?>" />
                </label>
            </div>
            <?php } ?>
            <div class="clearfix"></div>
            <?php
            }

            $detect = new Mobile_Detect;

            ?>

            <div id="loginForm">

                <div class="loginFormUsername">
                    <!--  <?php echo $this->t('{notakey:notakey:please_enter_username}') ?> -->

                    <input type="text" value="<?php echo htmlspecialchars(isset($this->data['username_hint']))?$this->data['username_hint']:''; ?>" name="username" id="username" placeholder="<?php echo $this->t('{login:username}'); ?>" tabindex="1" maxlength="100">
                </div>
                <?php
                if ($this->data['rememberMeEnabled']) {
                // display the remember me checkbox (keep me logged in)
                ?>
                <div class="loginFormRememberMe">

                    <input type="checkbox" id="remember_me" tabindex="4" <?php echo ($this->data['rememberMeChecked']) ? 'checked="checked"' : ''; ?> name="remember_me" value="Yes"/>
                    <small><?php echo $this->t('{login:remember_me}'); ?></small>

                </div>
                <?php
                }
                ?>
                <div class="regularSubmit">
                    <input type="button" id="regularsubmit" tabindex="4" value="<?php echo $this->t('{login:login_button}'); ?>" onClick=" this.value='<?php echo $this->t('{login:processing}'); ?>'; this.disabled=true; this.form.submit(); return true;" />
                </div>
                <div class="mobileSubmit">
                    <input type="button" tabindex="4" id="mobilesubmit" value="<?php echo $this->t('{login:login_button}'); ?>" onClick=" this.value='<?php echo $this->t('{login:processing}'); ?>'; this.disabled=true; this.form.submit(); return true;" />
                </div>
            </div>
            <input type="hidden" name="ReturnTo" value="<?php echo htmlspecialchars($this->data['return_to']); ?>">
            <input type="hidden" name="State" value="<?php echo htmlspecialchars($this->data['state_id']); ?>">
        </form>
    </div>
</div>
<?php
}else{
?>
        <div style="clear:both;"></div><div class="control-group ">
            <?php $selected_svc = $this->data['service_list'][$this->data['selected_service']]; ?>
            <div id="spLoginLogo">
                <img alt="<?php echo $selected_svc['name']; ?> logo"  src="<?php echo $selected_svc['service_logo']; ?>" />
            </div>
          <div class="clearfix"></div>
          <div class="control-group" >
                <div class="float-l" id="progressind">
                  <img height="40" src="/<?php echo $this->data['baseurlpath']; ?>module/notakey/resources/loading.gif" width="40" >
                </div>
                <div class="float-l" id="progresstxt" style="max-width: 30rem;">
                    <?php echo $this->t('{notakey:notakey:please_proceed_on_mobile}') ?>
                </div>
          </div>
          <div class="clearfix"></div>
        </div>
<?php
}



$this->includeAtTemplateBase('includes/footer.php');
