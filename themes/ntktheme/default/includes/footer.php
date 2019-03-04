<?php
if(!empty($this->data['htmlinject']['htmlContentPost'])) {
	foreach($this->data['htmlinject']['htmlContentPost'] AS $c) {
		echo $c;
	}
}
?>
		</div>
    </div>
    <footer class="footer">
      <div class="container">
        <p><small>Copyright © <?php echo date("Y", (is_readable('/var/simplesamlphp/BUILDTS'))?@trim(file_get_contents('/var/simplesamlphp/BUILDTS')):time()); ?> Notakey Latvia SIA, v<?php echo $this->configuration->getVersion(); ?></small></p>
      </div>
    </footer>
</body>
</html>
