package co.krypt.kryptonite.devices;

import android.support.v4.util.Pair;
import android.support.v7.widget.RecyclerView;
import android.text.format.DateUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;

import java.util.List;

import co.krypt.kryptonite.R;
import co.krypt.kryptonite.log.SignatureLog;
import co.krypt.kryptonite.pairing.Pairing;
import co.krypt.kryptonite.silo.Silo;

public class DevicesRecyclerViewAdapter extends RecyclerView.Adapter<DevicesRecyclerViewAdapter.ViewHolder> {

    private final List<Pair<Pairing, SignatureLog>> devicesAndLastLogs;
    private final OnDeviceListInteractionListener mListener;

    public DevicesRecyclerViewAdapter(List<Pair<Pairing, SignatureLog>> items, OnDeviceListInteractionListener listener) {
        devicesAndLastLogs = items;
        mListener = listener;
    }

    public void setPairings(List<Pair<Pairing, SignatureLog>> newPairings) {
        devicesAndLastLogs.clear();
        for (Pair<Pairing, SignatureLog> pairingAndLastLog : newPairings) {
            devicesAndLastLogs.add(pairingAndLastLog);
        }
        notifyDataSetChanged();
    }

    @Override
    public ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.device, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(final ViewHolder holder, final int position) {
        holder.device = devicesAndLastLogs.get(position).first;
        holder.lastLog = devicesAndLastLogs.get(position).second;

        holder.deviceName.setText(devicesAndLastLogs.get(position).first.workstationName);
        if (holder.lastLog != null) {
            holder.lastCommand.setText(holder.lastLog.command);
            holder.lastCommandTime.setText(DateUtils.getRelativeTimeSpanString(holder.lastLog.unixSeconds * 1000, System.currentTimeMillis(), 1000));
        }

        holder.unpairButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Silo.shared(v.getContext()).unpair(holder.device);
            }
        });

       holder.moreButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (null != mListener) {
                    // Notify the active callbacks interface (the activity, if the
                    // fragment is attached to one) that an item has been selected.
                    mListener.onListFragmentInteraction(holder.device);
                }
            }
        });
    }

    @Override
    public int getItemCount() {
        return devicesAndLastLogs.size();
    }

    public class ViewHolder extends RecyclerView.ViewHolder {
        public final View mView;
        public final TextView deviceName;
        public final TextView lastCommand;
        public final TextView lastCommandTime;
        public final Button unpairButton;
        public final Button moreButton;
        public Pairing device;
        public SignatureLog lastLog;

        public ViewHolder(final View view) {
            super(view);
            mView = view;
            deviceName = (TextView) view.findViewById(R.id.deviceName);
            lastCommand = (TextView) view.findViewById(R.id.lastCommandText);
            lastCommandTime = (TextView) view.findViewById(R.id.lastCommandTimeText);
            unpairButton = (Button) view.findViewById(R.id.unpairButton);
            moreButton = (Button) view.findViewById(R.id.moreButton);
        }

        @Override
        public String toString() {
            return super.toString() + " '" + deviceName.getText() + "'";
        }
    }
}