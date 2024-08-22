<?php

class Eidas_RequestedAttribute {
  
  private $prefix;
  
  private $name;

  private $attrUri;

  private $nameFormat;

  private $isRequired;
  
  private $value;

  public function __construct($prefix, $name, $attrUri, $nameFormat, $isRequired, $value) {
    
    $this->prefix = $prefix;
    $this->name = $name;
    $this->attrUri = $attrUri;
    $this->nameFormat = $nameFormat;
    $this->isRequired = $isRequired;
    //cometar el value y oner el Firendly Name
    $this->value = $value;
  }

  public function getPrefix() {
    return $this->prefix;
  }

  public function getName() {
    return $this->name;
  }

  public function getAttrUri() {
    return $this->attrUri;
  }

  public function getNameFormat() {
    return $this->nameFormat;
  }

  public function getIsRequired() {
    return $this->isRequired;
  }
  
  public function getValue() {
    return $this->value;
  }

  public function setPrefix($prefix) {
    $this->prefix = $prefix;
  }

  public function setName($name) {
    $this->name = name;
  }

  public function setAttrUri($attrUri) {
    $this->attrUri = $attrUri;
  }

  public function setNameFormat($nameFormat) {
    return $this->nameFormat;
  }
  
  public function setIsRequired($isRequired) {
    return $this->isRequired;
  }

  public function toDOM($doc) {
    $elem = $doc->createElementNS(Constants::STORK_NS, $this->prefix . ':' . $this->name);
    $elem->setAttribute('Name', $this->attrUri);
    $elem->setAttribute('NameFormat', $this->nameFormat);
    $elem->setAttribute('isRequired', $this->isRequired);
    if( !empty($this->value) ) {
      $elem->setAttribute('Value', $this->value);
    }
    return $elem;
  }

}
