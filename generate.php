<?php
require_once "ProductKeyEncoder.php";

$pkeyFile = __DIR__ . "/pkeyconfig.xrm-ms";
$xmlContent = file_get_contents($pkeyFile);
$xml = simplexml_load_string($xmlContent);
$pkeyNode = $xml->xpath('./*[local-name()="license"]/*[local-name()="otherInfo"]/*[local-name()="infoTables"]/*[local-name()="infoList"]/*[local-name()="infoBin"][@name="pkeyConfigData"]');
$pkeyDataXml = base64_decode((string)$pkeyNode[0]);
$pkeyData = simplexml_load_string($pkeyDataXml);

$sku   = $_POST['sku'];
$count = (int)$_POST['count'];

$configs = $pkeyData->xpath('./*[local-name()="Configurations"]/*[local-name()="Configuration"]');
$ranges  = $pkeyData->xpath('./*[local-name()="KeyRanges"]/*[local-name()="KeyRange"]');

$selectedConfig = null;
foreach ($configs as $c) {
    if ((string)$c->RefGroupId === $sku) {
        $selectedConfig = $c;
        break;
    }
}
if (!$selectedConfig) die("SKU no encontrado.");

$validRanges = [];
foreach ($ranges as $r) {
    if ((string)$r->RefActConfigId === (string)$selectedConfig->ActConfigId && strtolower((string)$r->IsValid) === "true") {
        $validRanges[] = $r;
    }
}
if (empty($validRanges)) die("No hay rangos válidos para este SKU.");

$results = [];
for ($i = 0; $i < $count; $i++) {
    $range = $validRanges[array_rand($validRanges)];
    $serial = rand((int)$r->Start, (int)$r->End);
    $security = rand(0, 0x1FFFFFFFFFFFFF);
    $group = (int)$selectedConfig->RefGroupId;

    $key = new ProductKeyEncoder($group, $serial, $security, 0, '0x400', 0);
    $results[] = (string)$key;
}

echo implode("\n", $results);

?>
