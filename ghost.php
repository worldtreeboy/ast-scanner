<?php
public function storeVirus(Virus $virus)
{
	$ser = serialize($virus);
	$quoted = $this->pdo->quote($ser);
	$encoded = mb_convert_encoding($quoted, 'UTF-8', 'ISO-8859-1');

	try {
		$this->pdo->query("INSERT INTO virus_vault (virus) VALUES ($encoded)");
		return $this->pdo->lastInsertId();
	} catch (Exception $e) {
		throw new Exception("An error occured while locking away the dangerous virus!");
	}
}

public function fetchVirus(string $id)
{
	try {
		$quoted = $this->pdo->quote(intval($id));
		$result = $this->pdo->query("SELECT virus FROM virus_vault WHERE id == $quoted");
		if ($result !== false) {
			$row = $result->fetch(PDO::FETCH_ASSOC);
			if ($row && isset($row['virus'])) {
				return unserialize($row['virus']);
			}
		}
		return null;
	} catch (Exception $e) {
		echo "An error occured while fetching your virus... Run!";
		print_r($e);
	}
	return null;
}
?>
