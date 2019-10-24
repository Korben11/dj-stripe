"""
.. module:: dj-stripe.contrib.rest_framework.views.

    :synopsis: Views for the dj-stripe REST API.

.. moduleauthor:: Philippe Luickx (@philippeluickx)

"""

from django.http import Http404

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ...models import Customer, Subscription
from ...settings import CANCELLATION_AT_PERIOD_END, subscriber_request_callback
from .serializers import CreateSubscriptionSerializer, SubscriptionSerializer

import logging

logger = logging.getLogger(__name__)


class SubscriptionRestView(APIView):
    """API Endpoints for the Subscription object."""

    permission_classes = (IsAuthenticated,)

    def get(self, request, **kwargs):
        """
        Return the customer's valid subscriptions.

        Returns with status code 200.
        """
        customer, _created = Customer.get_or_create(
            subscriber=subscriber_request_callback(self.request)
        )

        serializer = SubscriptionSerializer(customer.subscriptions.all(), many=True)
        return Response(serializer.data)

    def post(self, request, **kwargs):
        """
        Create a new current subscription for the user.

        Returns with status code 201.
        """
        serializer = CreateSubscriptionSerializer(data=request.data)

        if serializer.is_valid():
            try:
                customer, _created = Customer.get_or_create(
                    subscriber=subscriber_request_callback(self.request)
                )
                customer.add_card(serializer.data["stripe_token"])
                charge_immediately = serializer.data.get("charge_immediately")
                if charge_immediately is None:
                    charge_immediately = True

                customer.subscribe(serializer.data["plan"], charge_immediately,
                                   metadata=serializer.data.get("metadata", None))
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            except Exception as ex:
                # TODO: Better error messages
                logger.debug(f'{type(ex)} {ex}')
                return Response(
                    "Something went wrong processing the payment.",
                    status=status.HTTP_400_BAD_REQUEST,
                )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SubscriptionDeleteRestView(APIView):
    """API Endpoints for the Subscription object."""

    permission_classes = (IsAuthenticated,)

    def get_object(self, pk):
        try:
            customer, _created = Customer.get_or_create(
                subscriber=subscriber_request_callback(self.request)
            )
            subscription = customer.subscriptions.get(id=pk)
            return subscription
        except Subscription.DoesNotExist:
            raise Http404

    def delete(self, request, pk, **kwargs):
        """
        Mark the customers chosen subscription as canceled.

        Returns with status code 204.
        """
        try:
            subscription = self.get_object(pk)
            subscription.cancel(at_period_end=CANCELLATION_AT_PERIOD_END)

            serializer = SubscriptionSerializer(subscription)

            return Response(serializer.data, status=status.HTTP_204_NO_CONTENT)
        except Exception:
            return Response(
                "Something went wrong cancelling the subscription.",
                status=status.HTTP_400_BAD_REQUEST,
            )
