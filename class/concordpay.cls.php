<?php
class Concordpay
{
    const ORDER_NEW = 'New';
    const ORDER_DECLINED = 'Declined';
    const ORDER_REFUND_IN_PROCESSING = 'RefundInProcessing';
    const ORDER_REFUNDED = 'Refunded';
    const ORDER_EXPIRED = 'Expired';
    const ORDER_PENDING = 'Pending';
    const ORDER_APPROVED = 'Approved';
    const ORDER_WAITING_AUTH_COMPLETE = 'WaitingAuthComplete';
    const ORDER_IN_PROCESSING = 'InProcessing';
    const ORDER_SEPARATOR = '#';

    const SIGNATURE_SEPARATOR = ';';

    const URL = "https://pay.concord.ua/api/";

    protected $secret_key = '';

    protected $module_id = '';

    public function __construct($module_id = 'ns_concordpay'){
        $this->module_id = $module_id;
    }

    protected $keysForResponseSignature = array(
        'merchantAccount',
        'orderReference',
        'amount',
        'currency'
    );

    /** @var array */
    protected $keysForSignature = array(
        'merchant_id',
        'order_id',
        'amount',
        'currency_iso',
        'description'
    );

    /**
     * @param $option
     * @param $keys
     * @return string
     */
    public function getSignature($option, $keys)
    {
        $hash = array();
        foreach ($keys as $dataKey) {
            if (!isset($option[$dataKey])) {
                $option[$dataKey] = '';
            }
            if (is_array($option[$dataKey])) {
                foreach ($option[$dataKey] as $v) {
                    $hash[] = $v;
                }
            } else {
                $hash [] = $option[$dataKey];
            }
        }
        $hash = implode(self::SIGNATURE_SEPARATOR, $hash);
        return hash_hmac('md5', $hash, $this->getSecretKey());
    }

    /**
     * @param $options
     * @return string
     */
    public function getRequestSignature($options)
    {
        return $this->getSignature($options, $this->keysForSignature);
    }

    /**
     * @param $options
     * @return string
     */
    public function getResponseSignature($options)
    {
        return $this->getSignature($options, $this->keysForResponseSignature);
    }

    /**
     * @param $response
     * @return bool|string
     */
    public function isPaymentValid($response)
    {
        $sign = $this->getResponseSignature($response);
        if ($sign != $response['merchantSignature']) {
            return 'An error has occurred during payment';
        }

        if ($response['transactionStatus'] == self::ORDER_APPROVED) {
            return true;
        }

        return false;
    }

    public function getPaymentMethodSettings()
    {
        $payment_method = commerce_payment_method_instance_load("{$this->module_id}|commerce_payment_{$this->module_id}");
        return $payment_method['settings'];
    }


    public function getSecretKey()
    {
        $settings = $this->getPaymentMethodSettings();
        return $settings['secret_key'];
    }
}
