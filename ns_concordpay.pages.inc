<?php

/**
 * @file
 * Page callbacks for Concordpay.
 */

/**
 * Callback function return page.
 */
function ns_concordpay_return_page_callback()
{
    $data = json_decode(file_get_contents("php://input"), TRUE);
    if(empty($data)){
        drupal_goto('<front>');
    }
    $cp = new Concordpay();
    list($orderId, ) = explode(concordpay::ORDER_SEPARATOR, $data['orderReference']);

    $paymentInfo = $cp->isPaymentValid($data);
    $order = commerce_order_load($orderId);

    if(!$order) exit();

    if($paymentInfo === TRUE) {
        $order_wrapper = entity_metadata_wrapper('commerce_order', $order);
        $paid_in_full = isset($order->data['commerce_payment_order_paid_in_full_invoked']);
        if(!$paid_in_full) ns_concordpay_create_transaction($order, $order_wrapper);
    }
}