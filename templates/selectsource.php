<?php
$this->data['header'] = $this->t('{multiauthexpanded:multiauth:select_source_header}');

$this->includeAtTemplateBase('includes/header.php');
?>

<h2><?php echo $this->t('{multiauthexpanded:multiauth:select_source_header}'); ?></h2>

<p><?php echo $this->t('{multiauthexpanded:multiauth:select_source_text}'); ?></p>

<ul>
<?php
foreach($this->data['sources'] as $source) {
	echo '<li><a href="?source=' . htmlspecialchars($source['config_name']) .
		'&AuthState=' . htmlspecialchars($this->data['authstate']) . '">' .
		htmlspecialchars($source['name']) . '</a></li>';
}
?>
</ul>

<?php $this->includeAtTemplateBase('includes/footer.php'); ?>
