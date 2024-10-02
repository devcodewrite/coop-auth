<?php

namespace Codewrite\CoopAuth;

use Zenoph\Notify\Enums\AuthModel;
use Zenoph\Notify\Enums\HTTPCode;
use Zenoph\Notify\Enums\TextMessageType;
use Zenoph\Notify\Request\SMSRequest;

class Sms
{
    /**
     * @param $msgTpl string message or message template.
     * @param $personalised bool make the message personalised set true or non personlised set false. 
     * @param $data array list of key-value pair of destinations and template values.
     * @param $callbackUrl string callback url for request delivery status.
     */
    public function send(string $msgTpl, array $data, $personalised = true, string $callbackUrl = null): Response
    {
        try {
            // create request subject
            $request = new SMSRequest();
            $request->setHost(env('sms.hostUrl'));
            //$request->setDeliveryCallback($callbackUrl ? $callbackUrl : env('sms.callbackUrl'), ContentType::JSON);
            $request->useSecureConnection(env('sms.useSecureConnection'));

            $request->setAuthModel(AuthModel::API_KEY);
            $request->setAuthApiKey(env('sms.apiKey'));

            // set message properties
            $request->setMessage($msgTpl, $personalised);
            $request->setMessageType(TextMessageType::TEXT);

            // message sender Id must be requested from account to be used
            $request->setSender(env('sms.defaultSenderID'));

            if (gettype($data[0]) === 'string') {
                $addedCount = $request->addDestinationsFromCollection($data);
            } else {
                foreach ($data as $info) {
                    $values = $this->getDestinationValue($msgTpl, $info);
                    $addedCount = $request->addPersonalisedDestination($info['phone'], false, $values);
                }
            }
            $msgResp = $request->submit();
            if ($msgResp->getHttpStatusCode() === HTTPCode::OK)
                return new Response("Message sent successfully!", true, $addedCount);
            else  return new Response("Message couldn't be sent", false, $addedCount);
        } catch (\Exception $ex) {
            return new Response($ex->getMessage(), false);
        }
    }

    protected function tagContents($string, $tag_open, $tag_close)
    {
        foreach (explode($tag_open, $string) as $key => $value) {
            if (strpos($value, $tag_close) !== FALSE) {
                $result[] = substr($value, 0, strpos($value, $tag_close));;
            }
        }
        return $result;
    }

    public function getDestinationValue($msgTpl, $item): array
    {
        $value = [];
        foreach ($this->tagContents($msgTpl, '{$', '}') as $field)
            array_push($value, $item[$field]);
        return $value;
    }
}
class Response
{
    public $status;
    public $message;
    public $msgCount;

    public function __construct(string $message = null, bool $status = false, $msgCount = 0)
    {
        $this->message = $message;
        $this->status = $status;
        $this->msgCount = $msgCount;
    }
    public function getStatus(): bool
    {
        return $this->status;
    }
    public function getMessage()
    {
        return $this->message;
    }

    public function getCount()
    {
        return $this->msgCount;
    }
}
