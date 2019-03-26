/*
 * Aurora Store
 * Copyright (C) 2019, Rahul Kumar Patel <whyorean@gmail.com>
 *
 * Aurora Store is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * Aurora Store is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Aurora Store.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */

package com.aurora.store.fragment;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ViewSwitcher;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.widget.NestedScrollView;

import com.aurora.store.ErrorType;
import com.aurora.store.R;
import com.aurora.store.exception.MalformedRequestException;
import com.aurora.store.fragment.details.AbstractHelper;
import com.aurora.store.fragment.details.ActionButton;
import com.aurora.store.fragment.details.BackToPlayStore;
import com.aurora.store.fragment.details.Beta;
import com.aurora.store.fragment.details.ClusterDetails;
import com.aurora.store.fragment.details.ExodusPrivacy;
import com.aurora.store.fragment.details.GeneralDetails;
import com.aurora.store.fragment.details.Permissions;
import com.aurora.store.fragment.details.Reviews;
import com.aurora.store.fragment.details.Screenshot;
import com.aurora.store.fragment.details.Share;
import com.aurora.store.fragment.details.SystemAppPage;
import com.aurora.store.fragment.details.Video;
import com.aurora.store.model.App;
import com.aurora.store.receiver.DetailsInstallReceiver;
import com.aurora.store.task.DetailsApp;
import com.aurora.store.utility.Log;
import com.aurora.store.utility.PackageUtil;
import com.aurora.store.view.ErrorView;

import java.util.concurrent.TimeUnit;

import butterknife.BindView;
import butterknife.ButterKnife;
import io.reactivex.Observable;
import io.reactivex.android.schedulers.AndroidSchedulers;
import io.reactivex.schedulers.Schedulers;

public class DetailsFragment extends BaseFragment implements BaseFragment.EventListenerImpl {

    public static App app;

    @BindView(R.id.view_switcher)
    ViewSwitcher mViewSwitcher;
    @BindView(R.id.content_view)
    LinearLayout layoutContent;
    @BindView(R.id.err_view)
    LinearLayout layoutError;
    @BindView(R.id.container)
    CoordinatorLayout mContainer;
    @BindView(R.id.scroll_view)
    NestedScrollView mScrollView;
    @BindView(R.id.btn_positive)
    Button mButton;

    private Context context;
    private DetailsApp mTaskHelper;
    private ActionButton mActionButton;
    private String packageName;
    private DetailsInstallReceiver mInstallReceiver;

    @Override
    public void onAttach(@NonNull Context context) {
        super.onAttach(context);
        this.context = context;
    }

    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_details, container, false);
        ButterKnife.bind(this, view);

        Bundle arguments = getArguments();
        if (arguments != null) {
            packageName = arguments.getString("PackageName");
            fetchDetails();
        }
        return view;
    }

    @Override
    public void onActivityCreated(@Nullable Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
        mInstallReceiver = new DetailsInstallReceiver(packageName);
        setErrorView(ErrorType.NO_APPS);
    }

    @Override
    public void onResume() {
        super.onResume();
        context.registerReceiver(mInstallReceiver, mInstallReceiver.getFilter());
        if (mActionButton != null)
            mActionButton.draw();
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        try {
            context.unregisterReceiver(mInstallReceiver);
            mActionButton = null;
            mTaskHelper = null;
            disposable.clear();
        } catch (Exception ignored) {
        }
    }

    private void fetchDetails() {
        mTaskHelper = new DetailsApp(getContext());
        disposable.add(Observable.fromCallable(() -> mTaskHelper.getInfo(packageName))
                .subscribeOn(Schedulers.io())
                .observeOn(AndroidSchedulers.mainThread())
                .subscribe(app -> {
                    switchViews(false);
                    draw(app);
                }, err -> {
                    Log.e(err.getMessage());
                    processException(err);
                }));
    }

    private void draw(App mApp) {
        app = mApp;
        drawButtons();
        disposable.add(Observable.just(
                new GeneralDetails(this, app),
                new Screenshot(this, app),
                new Reviews(this, app),
                new ExodusPrivacy(this, app),
                new Permissions(this, app),
                new Video(this, app),
                new BackToPlayStore(this, app),
                new Share(this, app),
                new SystemAppPage(this, app),
                new Beta(this, app))
                .zipWith(Observable.interval(16, TimeUnit.MILLISECONDS), (abstractHelper, interval) -> abstractHelper)
                .subscribeOn(Schedulers.io())
                .observeOn(AndroidSchedulers.mainThread())
                .doOnNext(AbstractHelper::draw)
                .subscribe());
        new ClusterDetails(this, app).draw();
    }

    public void drawButtons() {
        if (PackageUtil.isInstalled(context, app))
            app.setInstalled(true);
        mActionButton = new ActionButton(this, app);
        mActionButton.draw();
    }

    private void setErrorView(ErrorType errorType) {
        layoutError.removeAllViews();
        layoutError.addView(new ErrorView(context, errorType, errorType == ErrorType.NO_NETWORK ? retry() : close()));
    }

    private View.OnClickListener retry() {
        return v -> {
            fetchDetails();
            ((Button) v).setText(getString(R.string.action_retry_ing));
            ((Button) v).setEnabled(false);
        };
    }

    private View.OnClickListener close() {
        return v -> {
            if (getActivity() != null)
                getActivity().onBackPressed();
        };
    }

    private void switchViews(boolean showError) {
        if (mViewSwitcher.getCurrentView() == layoutContent && showError)
            mViewSwitcher.showNext();
        else if (mViewSwitcher.getCurrentView() == layoutError && !showError)
            mViewSwitcher.showPrevious();
    }

    @Override
    public void processException(Throwable e) {
        disposable.clear();
        if (e instanceof MalformedRequestException) {
            setErrorView(ErrorType.MALFORMED);
            switchViews(true);
        } else
            super.processException(e);
    }

    @Override
    public void onLoggedIn() {
        fetchDetails();
    }

    @Override
    public void onLoginFailed() {

    }

    @Override
    public void onNetworkFailed() {
        setErrorView(ErrorType.NO_NETWORK);
        switchViews(true);
    }
}