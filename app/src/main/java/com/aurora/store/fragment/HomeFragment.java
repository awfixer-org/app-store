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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.viewpager.widget.ViewPager;

import com.aurora.store.R;
import com.aurora.store.adapter.CategoryAdapter;
import com.aurora.store.manager.CategoryManager;
import com.aurora.store.task.CategoryList;
import com.aurora.store.utility.Log;
import com.aurora.store.utility.Util;
import com.google.android.material.tabs.TabLayout;

import butterknife.BindView;
import butterknife.ButterKnife;
import io.reactivex.Observable;
import io.reactivex.android.schedulers.AndroidSchedulers;
import io.reactivex.disposables.CompositeDisposable;
import io.reactivex.schedulers.Schedulers;

public class HomeFragment extends Fragment {

    @BindView(R.id.tabLayout)
    TabLayout mTabLayout;
    @BindView(R.id.tabPager)
    ViewPager mViewPager;

    private Context context;
    private CompositeDisposable disposable = new CompositeDisposable();

    @Override
    public void onAttach(@NonNull Context context) {
        super.onAttach(context);
        this.context = context;
    }

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setRetainInstance(true);
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_home, container, false);
        ButterKnife.bind(this, view);
        return view;
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        init();
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        disposable.clear();
        disposable.dispose();
    }

    private void init() {
        CategoryAdapter mTabAdapter = new CategoryAdapter(getChildFragmentManager());
        mTabAdapter.addFragment(new ExploreFragment(), getString(R.string.tab_explore));
        mTabAdapter.addFragment(new GamesFragment(), getString(R.string.tab_games));
        mTabAdapter.addFragment(new FamilyFragment(), getString(R.string.tab_family));

        mViewPager.setAdapter(mTabAdapter);
        mTabLayout.setupWithViewPager(mViewPager);
        mTabLayout.setTabMode(Util.isTabScrollable(context)
                ? TabLayout.MODE_SCROLLABLE
                : TabLayout.MODE_FIXED);
        attachIconsToTabs();

        CategoryManager mCategoryManager = new CategoryManager(getContext());
        if (mCategoryManager.categoryListEmpty())
            getCategoriesFromAPI();
    }

    private void attachIconsToTabs() {
        TabLayout.Tab mTab;
        mTab = mTabLayout.getTabAt(0);
        if (mTab != null)
            mTab.setIcon(R.drawable.ic_tab_explore);
        mTab = mTabLayout.getTabAt(1);
        if (mTab != null)
            mTab.setIcon(R.drawable.ic_tab_games);
        mTab = mTabLayout.getTabAt(2);
        if (mTab != null)
            mTab.setIcon(R.drawable.ic_tab_family);
    }

    private void getCategoriesFromAPI() {
        disposable.add(Observable.fromCallable(() -> new CategoryList(getContext())
                .getResult())
                .subscribeOn(Schedulers.io())
                .observeOn(AndroidSchedulers.mainThread())
                .subscribe(success -> {
                }, err -> Log.e(err.getMessage())));
    }
}
