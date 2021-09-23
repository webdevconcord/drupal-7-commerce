<?php

/**
 * Class Concordpay - API class.
 */
class Concordpay {
  const ORDER_NEW       = 'New';
  const ORDER_DECLINED  = 'Declined';
  const ORDER_REFUNDED  = 'Refunded';
  const ORDER_EXPIRED   = 'Expired';
  const ORDER_PENDING   = 'Pending';
  const ORDER_APPROVED  = 'Approved';
  const ORDER_SEPARATOR = '#';
  const CURRENCY_UAH    = 'UAH';

  const RESPONSE_TYPE_PAYMENT = 'payment';
  const RESPONSE_TYPE_REVERSE = 'reverse';

  const SIGNATURE_SEPARATOR = ';';

  const URL = "https://pay.concord.ua/api/";

  /**
   * ConcordPay Secret Key.
   *
   * @var string
   */
  protected $secret_key = '';

  /**
   * Module ID.
   *
   * @var mixed|string
   */
  protected $module_id = '';

  /**
   * ConcordPay constructor.
   *
   * @param string $module_id
   *   Module ID.
   */
  public function __construct(string $module_id = 'commerce_concordpay') {
    $this->module_id = $module_id;
  }

  /**
   * Array keys for generate response signature.
   *
   * @var string[]
   */
  protected $keysForResponseSignature = [
    'merchantAccount',
    'orderReference',
    'amount',
    'currency',
  ];

  /**
   * Array keys for generate request signature.
   *
   * @var string[]
   */
  protected $keysForSignature = [
    'merchant_id',
    'order_id',
    'amount',
    'currency_iso',
    'description',
  ];

  /**
   * Generate signature for operation.
   *
   * @param array $option
   *   Request or response data.
   * @param array $keys
   *   Keys for signature.
   *
   * @return string
   *   Signature hash.
   */
  public function getSignature($option, $keys) {
    $hash = [];
    foreach ($keys as $dataKey) {
      if (!isset($option[$dataKey])) {
        $option[$dataKey] = '';
      }
      if (is_array($option[$dataKey])) {
        foreach ($option[$dataKey] as $v) {
          $hash[] = $v;
        }
      }
      else {
        $hash[] = $option[$dataKey];
      }
    }
    $hash = implode(self::SIGNATURE_SEPARATOR, $hash);
    return hash_hmac('md5', $hash, $this->getSecretKey());
  }

  /**
   * Generate request signature.
   *
   * @param array $options
   *   Request data.
   *
   * @return string
   *   Request signature.
   */
  public function getRequestSignature($options) {
    return $this->getSignature($options, $this->keysForSignature);
  }

  /**
   * Generate response signature.
   *
   * @param array $options
   *   Response data.
   *
   * @return string
   *   Response signature.
   */
  public function getResponseSignature($options) {
    return $this->getSignature($options, $this->keysForResponseSignature);
  }

  /**
   * Checking is payment valid.
   *
   * @param array $response
   *   Response data.
   *
   * @return bool|string
   *   Validity response.
   */
  public function isPaymentValid($response) {
    $sign = $this->getResponseSignature($response);
    if ($sign !== $response['merchantSignature']) {
      watchdog('commerce_concordpay', 'Wrong signature received.', WATCHDOG_ERROR);
      return t('An error has occurred during payment');
    }

    if ($response['transactionStatus'] === self::ORDER_APPROVED) {
      return TRUE;
    }

    return FALSE;
  }

  /**
   * Payment method config.
   *
   * @return mixed
   *   Payment method settings.
   */
  public function getPaymentMethodSettings() {
    $payment_method = commerce_payment_method_instance_load(
      "{$this->module_id}|commerce_payment_{$this->module_id}"
    );
    return $payment_method['settings'];
  }

  /**
   * ConcordPay Secret Key.
   *
   * @return string
   *   Secret Key.
   */
  public function getSecretKey() {
    $settings = $this->getPaymentMethodSettings();
    return $settings['secret_key'];
  }

}
